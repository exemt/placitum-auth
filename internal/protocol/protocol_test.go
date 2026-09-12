package protocol

import "testing"

func TestParseRoundTrip(t *testing.T) {
	raw := []byte(`{
		"v":2,"rid":"abc","ray":"7b21c0a8-f3e1-4d5a-8c2e-91b04f6a1d03",
		"phase":"request","inspector":"ip",
		"deadline_ms":5,"audit_subject":"waf.audit.inspector.ip",
		"conn":{"client_ip":"203.0.113.1"},
		"http":{"method":"GET","uri":"/","args_size":0},
		"needs":[],"store":{"headers":null,"args":null,"body":null}
	}`)

	req, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if req.Conn.ClientIP != "203.0.113.1" {
		t.Fatalf("client_ip=%q", req.Conn.ClientIP)
	}

	if req.AuditSubject == nil || *req.AuditSubject != "waf.audit.inspector.ip" {
		t.Fatalf("audit_subject=%v", req.AuditSubject)
	}

	reply := NewReply(req, VerdictAllow)
	if _, err := reply.Marshal(); err != nil {
		t.Fatal(err)
	}
}

// Три объекта одной формы, и nil у каждого значит одно и то же: содержимого
// нет. Отличать "не просил" от "нечего класть" по локатору нельзя -- для этого
// есть needs.
func TestParseStore(t *testing.T) {
	raw := []byte(`{
		"v":2,"rid":"abc","phase":"request","inspector":"ip",
		"deadline_ms":5,"conn":{"client_ip":"203.0.113.1"},
		"http":{"method":"GET","uri":"/","args_size":9},
		"needs":["headers","args"],
		"store":{
			"headers":{"store":"hot","driver":"redis","key":"w7:abc:req:hdr","size":12},
			"args":{"store":"hot","driver":"redis","key":"w7:abc:req:arg","size":9},
			"body":null
		}
	}`)

	req, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if !req.Store.Headers.Placed() || req.Store.Headers.Key != "w7:abc:req:hdr" {
		t.Fatalf("headers=%v", req.Store.Headers)
	}

	if req.Store.Args.Size != 9 || req.HTTP.ArgsSize != 9 {
		t.Fatalf("args=%v inline size=%d", req.Store.Args, req.HTTP.ArgsSize)
	}

	if req.Store.Body.Placed() {
		t.Fatalf("body=%v", req.Store.Body)
	}

	if !req.Needed(NeedArgs) || req.Needed(NeedBody) {
		t.Fatalf("needs=%v", req.Needs)
	}
}

// Недоступный объект -- не то же, что отсутствующий: у него есть причина, и
// адресации при ней быть не должно.
func TestParseUnavailableWithAddress(t *testing.T) {
	raw := []byte(`{
		"v":2,"rid":"abc","phase":"request","inspector":"ip",
		"deadline_ms":5,"conn":{"client_ip":"203.0.113.1"},
		"http":{"method":"GET","uri":"/"},
		"store":{"body":{"unavailable":"oversize","driver":"redis","key":"k"}}
	}`)

	if _, err := Parse(raw); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseMissingRID(t *testing.T) {
	_, err := Parse([]byte(`{"v":2,"phase":"request","inspector":"ip","http":{"method":"GET","uri":"/"}}`))
	if err == nil {
		t.Fatal("expected error")
	}

	pe, ok := err.(*ParseError)
	if !ok || pe.RID != "" {
		t.Fatalf("%v", err)
	}
}

func TestScoreRange(t *testing.T) {
	r := NewReply(&Request{V: Version, RID: "1", Inspector: "ip"}, VerdictAllow)
	if err := r.WithScore(101); err == nil {
		t.Fatal("expected range error")
	}
}

// Секция sessions едет при любом вердикте; поля без значения опускаются.
func TestReplySessions(t *testing.T) {
	req := &Request{V: Version, RID: "abc", Inspector: "auth"}

	reply := NewReply(req, VerdictAllow)
	reply.Sessions = []Session{
		{Source: "corp", Kind: SessionOwn, User: "alice", ID: "k7f3", Verified: true,
			Issued: 1757232000, Expires: 1757260800, Groups: []string{"ops"}},
		{Source: "shop", Kind: SessionApp, ID: "sha256:ab", Verified: true},
	}

	raw, err := reply.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	want := `"sessions":[{"source":"corp","kind":"own","user":"alice","id":"k7f3",` +
		`"verified":true,"issued":1757232000,"expires":1757260800,"groups":["ops"]},` +
		`{"source":"shop","kind":"app","id":"sha256:ab","verified":true}]`

	if !contains(string(raw), want) {
		t.Fatalf("reply: %s", raw)
	}

	if contains(string(NewReplyBytes(t, req)), "sessions") {
		t.Fatal("reply without sessions must not print the section")
	}
}

func NewReplyBytes(t *testing.T, req *Request) []byte {
	t.Helper()

	raw, err := NewReply(req, VerdictAllow).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

// request_store -- объекты фазы запроса на фазе ответа: подглядывание входа
// читает форму оттуда.
func TestParseRequestStore(t *testing.T) {
	raw := []byte(`{
		"v":2,"rid":"abc","phase":"response","inspector":"auth",
		"deadline_ms":5,"conn":{"client_ip":"203.0.113.1"},
		"http":{"method":"POST","uri":"/api/login","args_size":0},
		"needs":["headers","body"],
		"store":{"headers":{"store":"hot","driver":"redis","key":"w7:abc:rsp:hdr","size":12},"args":null,"body":null},
		"request_store":{"headers":{"store":"hot","driver":"redis","key":"w7:abc:req:hdr","size":40},"args":null,
			"body":{"store":"hot","driver":"redis","key":"w7:abc:req","size":30}},
		"response":{"status":302,"upstream_ms":3}
	}`)

	req, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	if req.RequestStore == nil || !req.RequestStore.Body.Placed() ||
		req.RequestStore.Body.Key != "w7:abc:req" {
		t.Fatalf("request_store: %+v", req.RequestStore)
	}

	if req.Response == nil || req.Response.Status != 302 {
		t.Fatalf("response: %+v", req.Response)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}

	return -1
}
