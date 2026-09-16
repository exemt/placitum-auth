package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-auth/internal/otp"
	"github.com/exemt/placitum-auth/internal/protocol"
	"github.com/exemt/placitum-auth/internal/token"
)

func main() {
	var (
		servers = flag.String("servers", env("NATS_URL", "nats://127.0.0.1:4222"),
			"bus addresses, comma-separated")
		subject = flag.String("subject", env("WAF_AUTH_SUBJECT", "waf.req.auth"),
			"inspector subject")
		name = flag.String("inspector", env("WAF_AUTH_NAME", "auth"),
			"inspector name in the message")
		uri      = flag.String("uri", "/healthcheck", "request path")
		method   = flag.String("method", "GET", "request method")
		clientIP = flag.String("client-ip", "127.0.0.1", "conn.client_ip")
		profile  = flag.String("profile", "default", "route.profile value")
		expect   = flag.String("expect", "", "expected verdict: allow, redirect, deny")
		timeout  = flag.Duration("timeout", time.Second, "how long to wait for the answer")
		quiet    = flag.Bool("quiet", false, "print nothing, only set the exit code")
		totp     = flag.String("totp", "", "print the current TOTP code for a base32 secret and exit")
		identity = flag.String("open-identity", "",
			"decode an application identity (waf_id cookie) and exit")
		keyFile = flag.String("key-file", env("WAF_AUTH_APP_KEY_FILE", ""),
			"key file for --open-identity")
	)

	flag.Parse()

	if *totp != "" {
		code, err := otp.Code(*totp, time.Now(), otp.DefaultStep, otp.DefaultDigits)
		if err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			os.Exit(1)
		}

		fmt.Println(code)

		return
	}

	if *identity != "" {
		if err := openIdentity(*identity, *keyFile); err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			os.Exit(1)
		}

		return
	}

	err := run(*servers, *subject, *name, *uri, *method, *clientIP, *profile, *expect,
		*timeout, *quiet)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func openIdentity(raw, keyFile string) error {
	if keyFile == "" {
		return fmt.Errorf("--key-file is empty and WAF_AUTH_APP_KEY_FILE is not set")
	}

	secret, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	key, err := token.NewKey(secret)
	if err != nil {
		return err
	}

	id, err := key.OpenIdentity(raw, time.Now())
	if err != nil {
		return err
	}

	out, err := json.Marshal(id)
	if err != nil {
		return err
	}

	fmt.Println(string(out))

	return nil
}

func run(servers, subject, name, uri, method, clientIP, profile, expect string,
	timeout time.Duration, quiet bool) error {

	nc, err := nats.Connect(servers, nats.Timeout(timeout), nats.NoReconnect())
	if err != nil {
		return err
	}

	defer nc.Close()

	payload, err := json.Marshal(request(name, uri, method, clientIP, profile, timeout))
	if err != nil {
		return err
	}

	msg, err := nc.Request(subject, payload, timeout)
	if err != nil {
		return fmt.Errorf("no verdict from %s: %w", subject, err)
	}

	var reply protocol.Reply

	if err := json.Unmarshal(msg.Data, &reply); err != nil {
		return fmt.Errorf("malformed reply: %w", err)
	}

	if !quiet {
		out, _ := json.Marshal(reply)
		fmt.Println(string(out))
	}

	if expect != "" && reply.Verdict != expect {
		return fmt.Errorf("verdict is %q, expected %q", reply.Verdict, expect)
	}

	return nil
}

func request(name, uri, method, clientIP, profile string,
	timeout time.Duration) *protocol.Request {

	path, args, _ := strings.Cut(uri, "?")

	return &protocol.Request{
		V:          protocol.Version,
		RID:        fmt.Sprintf("%016x", time.Now().UnixNano()),
		Phase:      protocol.PhaseRequest,
		Inspector:  name,
		DeadlineMS: int(timeout.Milliseconds()),
		Node:       "probe",
		Conn: protocol.Conn{
			ClientIP:   clientIP,
			ClientPort: 12345,
			ServerIP:   "127.0.0.1",
			ServerPort: 8080,
		},
		HTTP: protocol.HTTP{
			Method:   method,
			Scheme:   "http",
			Host:     "probe.local",
			URI:      path,
			ArgsSize: int64(len(args)),
			Version:  "HTTP/1.1",
		},
		Needs: []string{protocol.NeedHeaders},
		Route: protocol.Route{ServerName: "probe.local", Location: "/", Profile: profile},
		Score: protocol.ScoreState{DenyAt: 100},
	}
}

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}

	return def
}
