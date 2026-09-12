package livelist

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

type fakeBlobs struct {
	objs map[string][]byte
}

func (b *fakeBlobs) Object(_ context.Context, key string) ([]byte, error) { return b.objs[key], nil }

func (b *fakeBlobs) Objects(_ context.Context, keys []string) ([][]byte, error) {
	out := make([][]byte, len(keys))
	for i, k := range keys {
		out[i] = b.objs[k]
	}

	return out, nil
}

var testKey = Key{'k', 'e', 'y', '-', 'o', 'f', '-', 't', 'h', 'e', '-', 'e', 'p', 'o', 'c', 'h'}

func mirror() (*Mirror, *set, *fakeBlobs) {
	st := &set{name: "shop", comp: newComposition(), ready: true, epoch: 7, seq: 10, key: testKey, typ: typeString}
	blobs := &fakeBlobs{objs: map[string][]byte{}}
	m := &Mirror{log: slog.Default(), blobs: blobs, sets: map[string]*set{"shop": st}}

	return m, st, blobs
}

func str(op uint8, value string, exp int64, reason string) packRecord {
	return packRecord{op: op, value: value, exp: exp, reason: reason}
}

// stage кладёт пакет seq в Redis с хешем, посчитанным как у keeper.
func stage(st *set, blobs *fakeBlobs, seq uint64, recs ...packRecord) {
	hash := st.comp.hash
	seen := map[string]bool{}

	for k := range st.comp.entries {
		seen[k] = true
	}

	for _, r := range recs {
		if r.op == recAdd && !seen[r.value] {
			hash ^= SipHash(st.key, r.value)
			seen[r.value] = true
		}

		if r.op == recRemove && seen[r.value] {
			hash ^= SipHash(st.key, r.value)
			delete(seen, r.value)
		}
	}

	blobs.objs[diffKey(st.name, seq)] = pack(packHead{
		kind: kindPackage, typ: typeString, flags: flagReasons, epoch: st.epoch, seq: seq, hash: hash, key: st.key,
	}, recs)
}

// reason записи доезжает до зеркала: провайдер app читает из него логин.
func TestApplyKeepsReason(t *testing.T) {
	m, st, blobs := mirror()

	stage(st, blobs, 11,
		str(recAdd, "h1", time.Now().Add(time.Hour).UnixMilli(), "AUTH_LOGIN alice"),
		str(recAdd, "h2", 0, ""),
	)
	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 11, Op: opDiff})

	e, ok, ready := m.Lookup("shop", "h1")
	if !ok || !ready || e.Reason != "AUTH_LOGIN alice" || e.Expires == 0 {
		t.Fatalf("lookup: %+v %v %v", e, ok, ready)
	}

	if ok, ready := m.Contains("shop", "h2"); !ok || !ready {
		t.Fatalf("contains: %v %v", ok, ready)
	}

	stage(st, blobs, 12, str(recRemove, "h1", 0, ""))
	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 12, Op: opDiff})

	if _, ok, _ := m.Lookup("shop", "h1"); ok {
		t.Fatal("removed entry still found")
	}

	if st.seq != 12 || st.comp.hash != SipHash(st.key, "h2") {
		t.Fatalf("state: seq=%d", st.seq)
	}
}

// Истёкшая запись отсутствует до пакета keeper -- безопасная сторона.
func TestLookupExpired(t *testing.T) {
	m, st, blobs := mirror()

	stage(st, blobs, 11, str(recAdd, "old", time.Now().Add(-time.Second).UnixMilli(), "AUTH_LOGIN bob"))
	m.onFrame(st, frame{V: Version, Epoch: hexOf(7), Seq: 11, Op: opDiff})

	if _, ok, ready := m.Lookup("shop", "old"); ok || !ready {
		t.Fatalf("expired: ok=%v ready=%v", ok, ready)
	}

	if _, ok, ready := m.Lookup("nope", "old"); ok || ready {
		t.Fatal("unknown set must not be ready")
	}

	st.ready = false

	if _, ok, ready := m.Lookup("shop", "old"); ok || ready {
		t.Fatal("set without a snapshot must not be ready")
	}
}

/* Снапшот из объекта: состав, эпоха, ключ и номер берутся из заголовка. */
func TestSnapshotObjectBuildsTheSet(t *testing.T) {
	_, st, blobs := mirror()

	var key Key
	copy(key[:], "0123456789abcdef")

	recs := []packRecord{str(recAdd, "a", 0, "r-a"), str(recAdd, "b", 0, "")}
	hash := SipHash(key, "a") ^ SipHash(key, "b")

	data := pack(packHead{kind: kindSnapshot, typ: typeString, flags: flagReasons, epoch: 99, seq: 500, hash: hash, key: key}, recs)
	blobs.objs["waf:snap:shop:x"] = data

	head, out, err := unpack(data)
	if err != nil || head.kind != kindSnapshot || len(out) != 2 || out[0].reason != "r-a" {
		t.Fatalf("unpack: %+v %v", head, err)
	}

	comp := newComposition()
	for _, r := range out {
		comp.apply(head.key, head.typ, r)
	}

	if comp.hash != head.hash || comp.size() != 2 {
		t.Fatalf("composition from the object: hash %x vs %x", comp.hash, head.hash)
	}

	_ = st
}
