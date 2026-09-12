/*
 * Поколение источников и профилей калитки из JetStream KV.
 *
 * Манифест несёт текст source.yaml, profile.yaml и users.yaml -- ровно те
 * файлы, что лежат в каталоге поколения (sources/<имя>/ и profiles/<имя>/).
 * Поэтому здесь нет ни разбора, ни валидации: файлы раскладываются на диск, и
 * дальше их читает тот же загрузчик, что читает bootstrap-каталог. Третьей
 * реализации разбора не появляется, а расхождение контроллера с инспектором
 * видно как apply_failed в пульсе.
 *
 * v2: две карты вместо одной -- sources и profiles. Манифест v1 (без
 * источников) отвергается: его файлы новый загрузчик всё равно не разберёт.
 *
 * Канон хеша совпадает с контроллером -- docs/inspector-config-distribution.md.
 */

package desired

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/exemt/placitum-auth/internal/config"
)

const (
	Bucket         = "WAF_DESIRED"
	Key            = "policy/auth"
	DefaultProfile = "default"

	ApplyOK     = "ok"
	ApplyFailed = "apply_failed"

	// treeDir -- имя каталога с применённым поколением внутри DataDir. Рядом
	// живут .next и .prev: подмена каталогом, а не пофайловая.
	treeDir = "profiles"
)

type File struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Entry struct {
	Files []File `json:"files"`
}

type Manifest struct {
	V          int              `json:"v"`
	Rev        int              `json:"rev"`
	ConfigHash string           `json:"config_hash"`
	Sources    map[string]Entry `json:"sources"`
	Profiles   map[string]Entry `json:"profiles"`
	// Settings -- свойства процесса из каталога; нет в старых поколениях.
	Settings *Settings `json:"settings,omitempty"`
}

func Parse(raw []byte) (*Manifest, error) {
	var m Manifest

	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	if m.V != 2 {
		return nil, fmt.Errorf("manifest: unsupported v %d", m.V)
	}

	if m.Rev < 1 {
		return nil, fmt.Errorf("manifest: rev must be positive")
	}

	if _, ok := m.Profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("manifest: profile %q is missing", DefaultProfile)
	}

	for kind, entries := range map[string]map[string]Entry{
		"source": m.Sources, "profile": m.Profiles,
	} {
		for name, entry := range entries {
			if name == "" || len(entry.Files) == 0 {
				return nil, fmt.Errorf("manifest: %s %q is empty", kind, name)
			}

			if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
				return nil, fmt.Errorf("manifest: bad %s name %q", kind, name)
			}

			for _, file := range entry.Files {
				/*
				 * Имя файла кладётся на диск, поэтому проверяется здесь, а не в
				 * доверии к контроллеру: "../" в имени -- это запись мимо
				 * каталога поколения.
				 */
				if file.Name == "" || strings.ContainsAny(file.Name, `/\`) ||
					file.Name == "." || file.Name == ".." {
					return nil, fmt.Errorf("manifest: %s %q has a bad file name %q",
						kind, name, file.Name)
				}
			}
		}
	}

	if err := m.Settings.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	got := HashWith(m.Sources, m.Profiles, m.Settings)

	if m.ConfigHash != "" && m.ConfigHash != got {
		return nil, fmt.Errorf("manifest: config_hash mismatch: got %s want %s",
			got, m.ConfigHash)
	}

	m.ConfigHash = got

	return &m, nil
}

// Hash -- канон общий с контроллером: секция sources, затем profiles, внутри
// секции имена по алфавиту, разделители -- нулевые байты.
func Hash(sources, profiles map[string]Entry) string {
	return HashWith(sources, profiles, nil)
}

// HashWith -- канон целиком: секции, затем settings, если блок есть.
func HashWith(sources, profiles map[string]Entry, settings *Settings) string {
	sum := sha256.New()

	for _, section := range []struct {
		label   string
		entries map[string]Entry
	}{
		{"sources", sources},
		{"profiles", profiles},
	} {
		_, _ = sum.Write([]byte(section.label))
		_, _ = sum.Write([]byte{0})

		names := make([]string, 0, len(section.entries))

		for name := range section.entries {
			names = append(names, name)
		}

		sort.Strings(names)

		for _, name := range names {
			_, _ = sum.Write([]byte(name))
			_, _ = sum.Write([]byte{0})

			for _, file := range section.entries[name].Files {
				_, _ = sum.Write([]byte(file.Name))
				_, _ = sum.Write([]byte{0})
				_, _ = sum.Write([]byte(file.Text))
				_, _ = sum.Write([]byte{0})
			}
		}
	}

	writeSettings(sum, settings)

	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

func sortedNames(entries map[string]Entry) []string {
	names := make([]string, 0, len(entries))

	for name := range entries {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func (m *Manifest) Names() []string       { return sortedNames(m.Profiles) }
func (m *Manifest) SourceNames() []string { return sortedNames(m.Sources) }

/* --- применение ------------------------------------------------------------ */

/*
 * Apply раскладывает поколение рядом с боевым каталогом и переключает store на
 * него. Провал разбора не трогает ни каталог, ни снимок: поколение, из-за
 * которого калитка перестанет пускать людей, применять нельзя даже частично.
 */
func Apply(store *config.Store, dataDir string, m *Manifest) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}

	staging := filepath.Join(dataDir, ".next")
	prev := filepath.Join(dataDir, ".prev")
	live := filepath.Join(dataDir, treeDir)

	_ = os.RemoveAll(staging)

	if err := write(staging, m); err != nil {
		_ = os.RemoveAll(staging)

		return err
	}

	_ = os.RemoveAll(prev)

	lived := true

	if err := os.Rename(live, prev); err != nil {
		if !os.IsNotExist(err) {
			_ = os.RemoveAll(staging)

			return fmt.Errorf("park live: %w", err)
		}

		lived = false
	}

	if err := os.Rename(staging, live); err != nil {
		if lived {
			_ = os.Rename(prev, live)
		}

		_ = os.RemoveAll(staging)

		return fmt.Errorf("promote staging: %w", err)
	}

	if err := store.ReloadFrom(live); err != nil {
		/*
		 * Профиль не разобрался. Возвращаем прежнее дерево и перечитываем его:
		 * иначе процесс остался бы с каталогом, которого он сам не принимает.
		 */
		_ = os.RemoveAll(live)

		if lived {
			if restore := os.Rename(prev, live); restore == nil {
				_ = store.ReloadFrom(live)
			}
		}

		return err
	}

	_ = os.RemoveAll(prev)

	return nil
}

func write(dir string, m *Manifest) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	for sub, entries := range map[string]map[string]Entry{
		"sources": m.Sources, "profiles": m.Profiles,
	} {
		for name, entry := range entries {
			at := filepath.Join(dir, sub, name)

			if err := os.MkdirAll(at, 0o750); err != nil {
				return err
			}

			for _, file := range entry.Files {
				// 0600: в users.yaml лежат хеши паролей, читать их посторонним
				// незачем даже внутри контейнера.
				if err := os.WriteFile(filepath.Join(at, file.Name),
					[]byte(file.Text), 0o600); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

/* --- наблюдение ------------------------------------------------------------ */

// Applied -- то, что уходит в кадр присутствия. Читают без блокировки.
type Applied struct {
	mu    sync.RWMutex
	hash  string
	rev   int
	apply string
	names []string
}

func (a *Applied) Snapshot() (hash string, rev int, apply string, names []string) {
	if a == nil {
		return "", 0, "", nil
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.hash, a.rev, a.apply, append([]string(nil), a.names...)
}

func (a *Applied) set(hash string, rev int, apply string, names []string) {
	a.mu.Lock()
	a.hash = hash
	a.rev = rev
	a.apply = apply
	a.names = append([]string(nil), names...)
	a.mu.Unlock()
}

/*
 * Watch держит подписку на ключ поколения. Нет ключа -- Applied пустой, процесс
 * остаётся на bootstrap-каталоге: контур без контроллера обязан работать.
 */
func Watch(
	ctx context.Context,
	nc *nats.Conn,
	store *config.Store,
	dataDir string,
	level *slog.LevelVar,
	log *slog.Logger,
) (*Applied, error) {
	applied := &Applied{}

	js, err := jetstream.New(nc)
	if err != nil {
		return nil, err
	}

	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket:  Bucket,
		History: 5,
	})
	if err != nil {
		return nil, err
	}

	watcher, err := kv.Watch(ctx, Key)
	if err != nil {
		return nil, err
	}

	go func() {
		defer watcher.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case entry, ok := <-watcher.Updates():
				if !ok {
					return
				}

				if entry == nil {
					continue
				}

				switch entry.Operation() {
				case jetstream.KeyValueDelete, jetstream.KeyValuePurge:
					continue
				}

				m, err := Parse(entry.Value())
				if err != nil {
					log.Warn("desired rejected", "error", err.Error())

					continue
				}

				hash, rev, apply, names := applied.Snapshot()

				if apply == ApplyOK && hash == m.ConfigHash && rev == m.Rev {
					continue
				}

				if err := Apply(store, dataDir, m); err != nil {
					/*
					 * В пульсе остаётся старый hash: он и есть то, по чему
					 * контроллер считает сходимость флота. Врать про
					 * применённое поколение нельзя.
					 */
					log.Error("desired apply failed",
						"rev", m.Rev,
						"hash", m.ConfigHash,
						"error", err.Error(),
					)
					applied.set(hash, rev, ApplyFailed, names)

					continue
				}

				applied.set(m.ConfigHash, m.Rev, ApplyOK, m.Names())

				// Порог -- после подмены профилей: поколение применяется целиком
				// или никак, и уровень битого поколения не должен вступать в силу.
				m.Settings.apply(level, log)

				log.Info("desired applied",
					"rev", m.Rev,
					"hash", m.ConfigHash,
					"sources", m.SourceNames(),
					"profiles", m.Names(),
				)
			}
		}
	}()

	return applied, nil
}

/*
 * Bootstrap поднимает уже применённое поколение при старте: рестарт до того,
 * как watch догнал KV, не должен откатывать процесс на файлы из образа.
 */
func Bootstrap(store *config.Store, dataDir string, log *slog.Logger) bool {
	if dataDir == "" {
		return false
	}

	live := filepath.Join(dataDir, treeDir)

	// Путь с подкаталогом profiles/ отличает поколение новой формы: старое
	// дерево (плоское, v1) здесь не находится и тихо уступает bootstrap-каталогу,
	// а живой манифест из KV перекладывает всё заново.
	if _, err := os.Stat(filepath.Join(live, "profiles", DefaultProfile,
		"profile.yaml")); err != nil {
		return false
	}

	if err := store.ReloadFrom(live); err != nil {
		log.Warn("applied generation is unusable, falling back to bootstrap profiles",
			"dir", live, "error", err.Error())

		return false
	}

	log.Info("applied generation restored", "dir", live)

	return true
}
