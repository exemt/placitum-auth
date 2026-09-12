package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/*
 * Демо-каталог стенда обязан грузиться. Профили в образ не едут -- их
 * доставляет контроллер поколением, а стенд монтирует свой каталог поверх
 * образа (deploy/auth/profiles платформы). Сломанный файл не должен
 * обнаруживаться на стенде: загрузка отвергает поколение целиком.
 *
 * Каталог ищется вверх по дереву. Вне платформы -- в отдельном репозитории
 * или в стадии сборки образа -- тест честно пропускается: проверять там нечего.
 */
func TestStandCatalogLoads(t *testing.T) {
	store, err := LoadProfiles(standCatalog(t), slog.Default())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	snap := store.Current()

	for _, name := range []string{DefaultName, "code", "observe"} {
		p, ok := snap.Profile(name)
		if !ok {
			t.Fatalf("profile %s is missing, got %v", name, snap.Names())
		}

		if p.Name != name {
			t.Fatalf("profile %s carries name %q", name, p.Name)
		}

		// Все поставляемые профили не-off, и ссылка обязана быть разрешена.
		if p.Src == nil {
			t.Fatalf("profile %s has no resolved source", name)
		}
	}

	src, ok := snap.Source("default")
	if !ok || len(src.Users) == 0 {
		t.Fatal("default source has no users file attached")
	}

	// Форма ищется по адресу: два источника на один login.uri означали бы, что
	// отвечает случайный.
	if got, ok := snap.ByLoginURI("/waf/code"); !ok || got.Name != "code" {
		t.Fatalf("login.uri lookup broken: %v %v", got, ok)
	}

	// Roster общий на процесс -- загрузка обязана это удержать.
	if snap.Roster().Prefix != "auth:" {
		t.Fatalf("roster prefix %q", snap.Roster().Prefix)
	}
}

// standCatalog находит демо-каталог стенда, поднимаясь от пакета к корню.
func standCatalog(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	for {
		candidate := filepath.Join(dir, "deploy", "auth", "profiles")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("стендовый каталог профилей не найден: прогон вне платформы")
		}

		dir = parent
	}
}

/* --- сборка временного каталога -------------------------------------------- */

type tree map[string]string

func writeTree(t *testing.T, files tree) string {
	t.Helper()

	dir := t.TempDir()

	for name, body := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))

		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	return dir
}

const testUsers = "users:\n  - login: ivanov\n    password: " +
	"\"$2a$12$RfCieXmylFauGSITCrA8L.Fx32uDoODW.7bsi4lG6eSIh5taEOzu6\"\n"

func sourceYaml(uri, cookie string) string {
	return "login:\n  uri: " + uri + "\nsession:\n  cookie: " + cookie +
		"\nprovider: local\nproviders:\n  local:\n    users: users.yaml\n"
}

/*
 * Межобъектные гарантии реестра: ровно они делают источники независимыми, а
 * ссылки -- живыми. Каждая ошибка обязана отвергнуть поколение целиком.
 */
func TestRegistryCrossChecks(t *testing.T) {
	base := tree{
		"sources/one/source.yaml":       sourceYaml("/waf/login", "waf_sid_one"),
		"sources/one/users.yaml":        testUsers,
		"profiles/default/profile.yaml": "mode: enforce\nsource: one\n",
	}

	if _, err := LoadProfiles(writeTree(t, base), slog.Default()); err != nil {
		t.Fatalf("baseline: %v", err)
	}

	cases := map[string]struct {
		extra tree
		want  string
	}{
		"общий login.uri": {
			extra: tree{
				"sources/two/source.yaml": sourceYaml("/waf/login", "waf_sid_two"),
				"sources/two/users.yaml":  testUsers,
			},
			want: "share login.uri",
		},
		"общая кука сессии": {
			extra: tree{
				"sources/two/source.yaml": sourceYaml("/waf/login-2", "waf_sid_one"),
				"sources/two/users.yaml":  testUsers,
			},
			want: "share session cookie",
		},
		"ссылка в пустоту": {
			extra: tree{
				"profiles/extra/profile.yaml": "mode: enforce\nsource: ghost\n",
			},
			want: "unknown source",
		},
		"identity.from в пустоту": {
			extra: tree{
				"sources/two/source.yaml": "login:\n  uri: /waf/login-2\n" +
					"identity:\n  from: ghost\nprovider: code\nproviders:\n" +
					"  code:\n    kind: totp\n    digits: 6\n    period: 30s\n" +
					"    skew: 1\n    users: ../one/users.yaml\n",
			},
			want: "identity.from",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := tree{}

			for k, v := range base {
				files[k] = v
			}

			for k, v := range c.extra {
				files[k] = v
			}

			_, err := LoadProfiles(writeTree(t, files), slog.Default())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// Без default инспектор не поднимается: маршрут без profile= остался бы без
// калитки.
func TestRegistryNeedsDefault(t *testing.T) {
	files := tree{
		"sources/one/source.yaml":     sourceYaml("/waf/login", "waf_sid_one"),
		"sources/one/users.yaml":      testUsers,
		"profiles/other/profile.yaml": "mode: enforce\nsource: one\n",
	}

	_, err := LoadProfiles(writeTree(t, files), slog.Default())
	if err == nil || !strings.Contains(err.Error(), DefaultName) {
		t.Fatalf("missing default was accepted: %v", err)
	}
}

// Поколение без единого источника законно, пока все профили off: подсистема
// объявлена и выключена.
func TestRegistryAllOff(t *testing.T) {
	files := tree{
		"profiles/default/profile.yaml": "mode: off\n",
	}

	store, err := LoadProfiles(writeTree(t, files), slog.Default())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if p, ok := store.Current().Profile(DefaultName); !ok || p.Src != nil {
		t.Fatalf("off profile resolved unexpectedly: %v %v", p, ok)
	}
}
