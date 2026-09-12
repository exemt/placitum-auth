package config

import (
	"testing"
	"time"
)

const minimal = `
mode: enforce
source: default
`

func TestDefaultsSurviveParsing(t *testing.T) {
	p, err := ParseProfile("default", []byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	if p.Gate.DenyResponse != "auth_required" || p.Gate.RedirectStatus != 303 {
		t.Fatalf("gate defaults lost: %+v", p.Gate)
	}

	if !p.RedirectsMethod("GET") || p.RedirectsMethod("POST") {
		t.Fatalf("redirect_methods default lost: %v", p.Gate.RedirectMethods)
	}
}

// Опечатка в имени поля -- ошибка загрузки, а не молча выигравшее умолчание.
// Сюда же попадают поля прежней модели (login, session, providers): они
// переехали в источник, и профиль с ними обязан не подняться, а не сделать вид.
func TestUnknownFieldIsRejected(t *testing.T) {
	for name, extra := range map[string]string{
		"опечатка":       "\nsesion:\n  ttl: 1h\n",
		"прежний login":  "\nlogin:\n  uri: /waf/login\n",
		"прежняя сессия": "\nsession:\n  ttl: 8h\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProfile("default", []byte(minimal+extra)); err == nil {
				t.Fatalf("stray key was accepted: %s", extra)
			}
		})
	}
}

// Источник обязателен всюду, кроме off: и enforce, и observe открывают сессии.
func TestSourceRequiredUnlessOff(t *testing.T) {
	for _, mode := range []string{"enforce", "observe"} {
		p, err := ParseProfile("default", []byte("mode: "+mode+"\n"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		if err := p.Validate(); err == nil {
			t.Fatalf("mode %s without source was accepted", mode)
		}
	}

	p, err := ParseProfile("default", []byte("mode: off\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("mode off without source rejected: %v", err)
	}
}

/*
 * Правила приёма чужих просьб. Ограничения повторяют капчу по духу: послабление
 * (skip) требует имени отправителя, ужесточение (reauth) можно слушать от всех;
 * глаголы, которые калитке нечем применить, не грузятся вовсе.
 */
func TestPriorRules(t *testing.T) {
	ok := map[string]string{
		"reauth от всех": "\ntrigger:\n  prior:\n    - from: \"*\"\n      accept: [reauth]\n",
		"skip с именем":  "\ntrigger:\n  prior:\n    - from: edge\n      accept: [skip]\n      codes: [HEALTHCHECK]\n",
		"reauth с осью":  "\ntrigger:\n  prior:\n    - from: repu\n      accept: [reauth]\n      apply: [session]\n",
	}

	for name, extra := range ok {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("default", []byte(minimal+extra))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			if err := p.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
		})
	}

	bad := map[string]string{
		"skip от всех":       "\ntrigger:\n  prior:\n    - from: \"*\"\n      accept: [skip]\n",
		"чужой challenge":    "\ntrigger:\n  prior:\n    - from: ip\n      accept: [challenge]\n",
		"чужой threshold":    "\ntrigger:\n  prior:\n    - from: ip\n      accept: [threshold]\n",
		"чужой note":         "\ntrigger:\n  prior:\n    - from: ip\n      accept: [note]\n",
		"неизвестный глагол": "\ntrigger:\n  prior:\n    - from: ip\n      accept: [block]\n",
		"ось не того глагола": "\ntrigger:\n  prior:\n    - from: repu\n" +
			"      accept: [reauth]\n      apply: [request]\n",
		"неизвестная ось": "\ntrigger:\n  prior:\n    - from: repu\n" +
			"      accept: [reauth]\n      apply: [subnet]\n",
		"пустой from":   "\ntrigger:\n  prior:\n    - from: \"\"\n      accept: [reauth]\n",
		"пустой accept": "\ntrigger:\n  prior:\n    - from: repu\n",
	}

	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("default", []byte(minimal+extra))
			if err != nil {
				return // отвергнут уже разбором -- тоже отказ
			}

			if err := p.Validate(); err == nil {
				t.Fatalf("profile was accepted: %s", extra)
			}
		})
	}
}

// Свежесть по умолчанию не нулевая: reauth без отсечки превращает вход в
// карусель, и умолчание обязано защищать от неё, а не полагаться на оператора.
func TestReauthAfterDefault(t *testing.T) {
	p, err := ParseProfile("default", []byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if p.Trigger.ReauthAfter.D() != 5*time.Minute {
		t.Fatalf("reauth_after default = %s, want 5m", p.Trigger.ReauthAfter.D())
	}
}

func TestValidationRejects(t *testing.T) {
	cases := map[string]string{
		"чужой код редиректа":     "\ngate:\n  redirect_status: 301\n",
		"метод в нижнем регистре": "\ngate:\n  redirect_methods: [get]\n",
		"пустая группа":           "\ngate:\n  groups: [\"\"]\n",
		"нет записи отказа":       "\ngate:\n  groups: [admins]\n  forbidden_response: \"\"\n",
	}

	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("default", []byte(minimal+extra))
			if err != nil {
				return // отвергнут уже разбором -- тоже отказ
			}

			if err := p.Validate(); err == nil {
				t.Fatalf("profile was accepted: %s", extra)
			}
		})
	}
}

/*
 * Допуск по группам: пара профилей на один источник -- общий пускает всех
 * вошедших, закрытый только своих, второго входа не требуется.
 */
func TestGateGroups(t *testing.T) {
	p, err := ParseProfile("admin", []byte(minimal+"\ngate:\n  groups: [admins, ops]\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Запись под 403 стоит умолчанием: профиль, назвавший группы, не обязан
	// помнить ещё и про каталог отказов.
	if p.Gate.ForbiddenResponse != "auth_forbidden" {
		t.Fatalf("forbidden_response = %q", p.Gate.ForbiddenResponse)
	}

	// Совпадения хватает одного, регистр и пробелы не считаются, сессия без
	// групп в закрытый профиль не проходит.
	for _, c := range []struct {
		groups []string
		want   bool
	}{
		{[]string{"ops"}, true},
		{[]string{"Admins"}, true},
		{[]string{" ops "}, true},
		{[]string{"readers"}, false},
		{nil, false},
	} {
		if got := p.Allows(c.groups); got != c.want {
			t.Fatalf("Allows(%v) = %v, want %v", c.groups, got, c.want)
		}
	}

	// Профиль без списка допуска пускает и того, у кого групп нет вовсе:
	// пустой список -- "не спрашиваем", а не "никого".
	open, err := ParseProfile("open", []byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !open.Allows(nil) {
		t.Fatal("profile without gate.groups denied a session without groups")
	}
}

/*
 * Профиль-спутник: пустые redirect_methods (401 всем без сессии) и тот же
 * источник, что у главной калитки маршрута. Формы у профиля не бывает вовсе --
 * форма принадлежит источнику.
 */
func TestCompanionProfile(t *testing.T) {
	p, err := ParseProfile("api", []byte(
		"mode: enforce\nsource: default\ngate:\n  redirect_methods: []\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if err := p.Validate(); err != nil {
		t.Fatalf("companion profile rejected: %v", err)
	}
}

/*
 * Правила по событиям: та же форма просьбы, что у остальных отправителей.
 * Просьба соседу доедет только с allow, поэтому на anonymous, invalid и
 * forbidden загрузчик пускает лишь глаголы записи маршрута.
 */
func TestEventRules(t *testing.T) {
	accepts := map[string]string{
		"skip captcha when signed in": "rules:\n  - {on: authenticated, to: captcha, do: skip, code: SIGNED_IN}\n",
		"discount modsec":             "rules:\n  - {on: authenticated, to: modsec, do: threshold, delta: -50}\n",
		"quiet vlai":                  "rules:\n  - {on: authenticated, to: vlai, do: off}\n",
		"drain a counter bucket":      "rules:\n  - {on: authenticated, to: counter, do: note, apply: session, value: -100, counter: abuse}\n",
		"mutate rewrite":              "rules:\n  - {on: authenticated, to: rewrite, do: mutate, group: mask, set: off}\n",
		"list net_all":                "rules:\n  - {on: invalid, list: gate_nets, write: net_all, ttl: 1h}\n",
		"list asn":                    "rules:\n  - {on: forbidden, list: gate_nets, write: asn, ttl: 1h}\n",
		"mark anonymous":              "rules:\n  - {on: anonymous, do: mark, marker: anon on gate}\n",
		"archive invalid":             "rules:\n  - {on: invalid, do: archive, set: on, ttl: 1h, when: [deny]}\n",
		"score forbidden":             "rules:\n  - {on: forbidden, do: score, value: 40}\n",
		"audit off":                   "rules:\n  - {on: authenticated, do: audit, set: off}\n",
		"list anonymous":              "rules:\n  - {on: anonymous, list: gate_anon, ttl: 10m}\n",
	}

	for name, extra := range accepts {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("default", []byte(minimal+extra))
			if err == nil {
				err = p.Validate()
			}

			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}

	rejects := map[string]string{
		"unknown on":            "rules:\n  - {on: sneeze, to: captcha, do: skip}\n",
		"neither do nor list":   "rules:\n  - {on: authenticated}\n",
		"both do and list":      "rules:\n  - {on: authenticated, to: captcha, do: skip, list: x, ttl: 1h}\n",
		"ask on anonymous":      "rules:\n  - {on: anonymous, to: captcha, do: skip}\n",
		"ask on invalid":        "rules:\n  - {on: invalid, to: counter, do: note, apply: ip, value: 10}\n",
		"control on forbidden":  "rules:\n  - {on: forbidden, to: vlai, do: off}\n",
		"unknown verb":          "rules:\n  - {on: authenticated, to: captcha, do: nuke}\n",
		"control without to":    "rules:\n  - {on: authenticated, do: off}\n",
		"control on conn":       "rules:\n  - {on: authenticated, to: vlai, do: off, apply: conn}\n",
		"threshold without delta": "rules:\n  - {on: authenticated, to: modsec, do: threshold}\n",
		"note without axis":     "rules:\n  - {on: authenticated, to: counter, do: note, value: 10}\n",
		"mutate without group":  "rules:\n  - {on: authenticated, to: rewrite, do: mutate, set: on}\n",
		"unknown write":         "rules:\n  - {on: invalid, list: x, write: country, ttl: 1h}\n",
		"write on an ask":       "rules:\n  - {on: authenticated, to: captcha, do: skip, write: net}\n",
		"mark without marker":   "rules:\n  - {on: authenticated, do: mark}\n",
		"audit without set":     "rules:\n  - {on: authenticated, do: audit}\n",
		"audit with to":         "rules:\n  - {on: authenticated, to: vlai, do: audit, set: on}\n",
		"score with to":         "rules:\n  - {on: authenticated, to: vlai, do: score, value: 10}\n",
		"ttl on skip":           "rules:\n  - {on: authenticated, to: vlai, do: skip, ttl: 1h}\n",
		"list without ttl":      "rules:\n  - {on: anonymous, list: gate_anon}\n",
		"bad code":              "rules:\n  - {on: authenticated, to: vlai, do: skip, code: \"плохой\"}\n",
	}

	for name, extra := range rejects {
		t.Run(name, func(t *testing.T) {
			p, err := ParseProfile("default", []byte(minimal+extra))
			if err == nil {
				err = p.Validate()
			}

			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
