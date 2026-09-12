package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-shared/netinfo"
)

type geoStub struct {
	values map[string][]string
	err    error
	calls  []string
}

func (g *geoStub) Write(_ context.Context, write, addr string) ([]string, error) {
	g.calls = append(g.calls, write+" "+addr)

	if g.err != nil {
		return nil, g.err
	}

	return g.values[write], nil
}

type listsStub struct{ writes []string }

func (l *listsStub) AddMany(name string, values []string, _ time.Duration, reason string) error {
	l.writes = append(l.writes, name+"="+strings.Join(values, ",")+"/"+reason)

	return nil
}

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func ruleOf(list, write string) config.EventRule {
	return config.EventRule{On: config.OnInvalid, List: list, Write: write,
		TTL: config.Duration(time.Hour)}
}

/* Адрес -- без кодера; подсеть и система -- у кодера, одной пачкой на строку. */
func TestWriteRuleScopes(t *testing.T) {
	geo := &geoStub{values: map[string][]string{
		netinfo.WriteNetAll: {"8.8.8.0/24", "8.0.0.0/9"},
		netinfo.WriteASN:    {"8.8.4.0/24", "8.8.8.0/24"},
	}}
	lists := &listsStub{}

	for _, r := range []config.EventRule{ruleOf("ip", ""), ruleOf("all", config.WriteNetAll),
		ruleOf("asn", config.WriteASN)} {
		if err := writeRule(context.Background(), geo, lists, quietLog, r, "8.8.8.143", "AUTH_INVALID"); err != nil {
			t.Fatal(err)
		}
	}

	want := "ip=8.8.8.143/AUTH_INVALID all=8.8.8.0/24,8.0.0.0/9/AUTH_INVALID asn=8.8.4.0/24,8.8.8.0/24/AUTH_INVALID"

	if got := strings.Join(lists.writes, " "); got != want {
		t.Fatalf("writes %s, want %s", got, want)
	}

	if len(geo.calls) != 2 {
		t.Fatalf("the coder is for net, net_all and asn only: %v", geo.calls)
	}
}

/* Кодер молчит: строка подсети -- ошибка вызывающему и без записи. */
func TestWriteRuleGeoDown(t *testing.T) {
	lists := &listsStub{}

	err := writeRule(context.Background(), &geoStub{err: netinfo.ErrUnavailable}, lists, quietLog,
		ruleOf("net", config.WriteNet), "8.8.8.143", "AUTH_INVALID")
	if !errors.Is(err, netinfo.ErrUnavailable) || len(lists.writes) != 0 {
		t.Fatalf("err %v, writes %v", err, lists.writes)
	}
}
