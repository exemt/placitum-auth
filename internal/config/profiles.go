/*
 * Реестр источников и профилей и его горячая перезагрузка.
 *
 * Каталог поколения несёт два подкаталога: sources/<имя>/source.yaml --
 * источники входа, profiles/<имя>/profile.yaml -- профили-калитки. Имена --
 * имена каталогов; файлы пользователей и своя страница входа лежат рядом с
 * source.yaml: они принадлежат источнику, а не профилю.
 *
 * Снимок неизменяем и подменяется целиком: правка одного файла не должна
 * оставлять контур в состоянии "половина старого, половина нового". Ошибка
 * разбора любого файла отвергает всё поколение -- действующий набор при этом
 * не трогают, как у modsec с его apply_failed.
 *
 * Межобъектные гарантии живут здесь, потому что одному файлу соседей не
 * видно: у формы ровно один источник (login.uri уникален), у пространства
 * сессий ровно один источник (session.cookie уникальна), профиль ссылается на
 * существующий источник, а identity.from -- на существующий чужой.
 *
 * Отпечаток -- имя, размер и mtime файлов. Читать содержимое раз в секунду
 * ради сравнения незачем: правят файлы руками, а не гонкой записей.
 */

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	profileFile   = "profile.yaml"
	sourceFile    = "source.yaml"
	loginPageFile = "login.html"

	profilesDir = "profiles"
	sourcesDir  = "sources"
)

type Snapshot struct {
	Gen         int64
	Fingerprint string

	profiles     map[string]*Profile
	sources      map[string]*Source
	byLogin      map[string]*Source
	profileNames []string
	sourceNames  []string
	roster       Roster
}

// Roster -- общая на процесс секция отзыва. Источники обязаны объявлять её
// одинаково, это проверяется при загрузке.
func (s *Snapshot) Roster() Roster {
	if s == nil {
		return Roster{}
	}

	return s.roster
}

func (s *Snapshot) Profile(name string) (*Profile, bool) {
	if s == nil {
		return nil, false
	}

	if name == "" {
		name = DefaultName
	}

	p, ok := s.profiles[name]

	return p, ok
}

func (s *Snapshot) Source(name string) (*Source, bool) {
	if s == nil {
		return nil, false
	}

	src, ok := s.sources[name]

	return src, ok
}

/*
 * ByLoginURI нужен HTTP-процессу: к нему приходят по адресу формы, а не по
 * маршруту приложения, и route.profile там взяться неоткуда. Форма
 * принадлежит источнику, поэтому и отвечает по адресу источник.
 */
func (s *Snapshot) ByLoginURI(uri string) (*Source, bool) {
	if s == nil {
		return nil, false
	}

	src, ok := s.byLogin[uri]

	return src, ok
}

// Sources -- источники в лексическом порядке имён. HTTP-процессу нужен обход:
// к нему приходят по адресу формы, и найти источник можно только по нему.
func (s *Snapshot) Sources() []*Source {
	if s == nil {
		return nil
	}

	out := make([]*Source, 0, len(s.sourceNames))

	for _, name := range s.sourceNames {
		out = append(out, s.sources[name])
	}

	return out
}

func (s *Snapshot) Names() []string {
	if s == nil {
		return nil
	}

	return s.profileNames
}

func (s *Snapshot) SourceNames() []string {
	if s == nil {
		return nil
	}

	return s.sourceNames
}

type Store struct {
	mu  sync.Mutex
	dir string
	log *slog.Logger
	cur atomic.Pointer[Snapshot]
	gen atomic.Int64
}

func LoadProfiles(dir string, log *slog.Logger) (*Store, error) {
	s := &Store{dir: dir, log: log}

	snap, err := s.read()
	if err != nil {
		return nil, err
	}

	s.cur.Store(snap)

	return s, nil
}

func (s *Store) Current() *Snapshot { return s.cur.Load() }

// Dir -- каталог, по которому сейчас читают. Нужен раскатке: она кладёт новое
// поколение рядом и переключает сюда.
func (s *Store) Dir() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.dir
}

/*
 * ReloadFrom переключает каталог и читает его целиком. Провал не трогает
 * действующий снимок и не меняет каталог: поколение, которое не разобралось,
 * не должно оставлять контур ни с половиной профилей, ни без них.
 */
func (s *Store) ReloadFrom(dir string) error {
	s.mu.Lock()
	prev := s.dir
	s.dir = dir
	s.mu.Unlock()

	snap, err := s.read()
	if err != nil {
		s.mu.Lock()
		s.dir = prev
		s.mu.Unlock()

		return err
	}

	s.cur.Store(snap)

	return nil
}

// Reload перечитывает каталог, если изменился отпечаток. Первое значение --
// была ли подмена.
func (s *Store) Reload() (bool, error) {
	fp, err := fingerprint(s.Dir())
	if err != nil {
		return false, err
	}

	if cur := s.cur.Load(); cur != nil && cur.Fingerprint == fp {
		return false, nil
	}

	snap, err := s.read()
	if err != nil {
		return false, err
	}

	s.cur.Store(snap)

	return true, nil
}

func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-tick.C:
			changed, err := s.Reload()
			if err != nil {
				// Битое поколение не подменяет действующее: калитка
				// продолжает работать по последнему исправному набору.
				s.log.Error("profiles reload failed", "error", err.Error())
				continue
			}

			if changed {
				snap := s.Current()
				s.log.Info("profiles reloaded",
					"gen", snap.Gen,
					"sources", snap.SourceNames(),
					"profiles", snap.Names(),
					"fingerprint", snap.Fingerprint,
				)
			}
		}
	}
}

func (s *Store) read() (*Snapshot, error) {
	dir := s.Dir()

	snap := &Snapshot{
		profiles: map[string]*Profile{},
		sources:  map[string]*Source{},
		byLogin:  map[string]*Source{},
	}

	if err := s.readSources(filepath.Join(dir, sourcesDir), snap); err != nil {
		return nil, err
	}

	if err := s.readProfiles(filepath.Join(dir, profilesDir), snap); err != nil {
		return nil, err
	}

	if _, ok := snap.profiles[DefaultName]; !ok {
		return nil, fmt.Errorf("profiles: %s is missing in %s", DefaultName, dir)
	}

	/*
	 * Профиль обязан ссылаться на существующий источник. Ссылка разрешается
	 * здесь один раз: горячему пути инспектора искать источник по имени на
	 * каждом запросе незачем.
	 */
	for _, name := range snap.profileNames {
		p := snap.profiles[name]
		if p.Source == "" {
			continue
		}

		src, ok := snap.sources[p.Source]
		if !ok {
			return nil, fmt.Errorf("profile %s: source names unknown source %q",
				name, p.Source)
		}

		p.Src = src
	}

	/*
	 * Стыкованный источник обязан знать первый: identity.from называет
	 * источник этого же процесса, и его cookie не должна совпадать со своей --
	 * иначе вход во второй стирал бы сессию первого.
	 */
	for _, name := range snap.sourceNames {
		src := snap.sources[name]
		if src.Identity.From == "" {
			continue
		}

		from, ok := snap.sources[src.Identity.From]
		if !ok {
			return nil, fmt.Errorf("source %s: identity.from names unknown source %q",
				name, src.Identity.From)
		}

		if from.Session.Cookie == src.Session.Cookie || from.Ticket.Cookie == src.Ticket.Cookie {
			return nil, fmt.Errorf("source %s: cookies must differ from those of %s",
				name, from.Name)
		}

		// Список ведёт один источник пары: два списка с одной cookie означали
		// бы, что быстрый путь открывает первый же пароль.
		if src.List.Enabled() && from.List.Enabled() && src.List.Cookie == from.List.Cookie {
			return nil, fmt.Errorf("source %s: list.cookie collides with %s; "+
				"only the last gate of a route should keep the list", name, from.Name)
		}
	}

	/*
	 * Источник и есть пространство сессий, поэтому кука уникальна: два
	 * источника с одной session.cookie -- это два множества пользователей,
	 * невольно открывающие двери друг друга. Раньше совпадение имён кук было
	 * способом склеить профили в пространство; теперь пространство склеивает
	 * ссылка source:, а совпадение кук -- ошибка конфигурации.
	 */
	for i, a := range snap.sourceNames {
		sa := snap.sources[a]

		for _, b := range snap.sourceNames[i+1:] {
			sb := snap.sources[b]

			if sa.Session.Cookie == sb.Session.Cookie {
				return nil, fmt.Errorf("sources %s and %s share session cookie %q; "+
					"a session space belongs to exactly one source", a, b, sa.Session.Cookie)
			}

			if sa.Ticket.Cookie == sb.Ticket.Cookie {
				return nil, fmt.Errorf("sources %s and %s share ticket cookie %q",
					a, b, sa.Ticket.Cookie)
			}
		}
	}

	/*
	 * Roster -- свойство процесса, а не источника: множество отзыва читается
	 * одно на всех, и два префикса означали бы два множества у одного
	 * инспектора. Секция остаётся в источнике, потому что там её ищут, но
	 * расхождение обязано быть ошибкой, а не молча выигравшим default.
	 */
	if len(snap.sourceNames) > 0 {
		first := snap.sources[snap.sourceNames[0]]

		for _, name := range snap.sourceNames[1:] {
			if snap.sources[name].Roster != first.Roster {
				return nil, fmt.Errorf("source %s: roster differs from %s; "+
					"the revoke set is shared by the whole process", name, first.Name)
			}
		}

		snap.roster = first.Roster
	} else {
		// Без единого источника отзыв и формы не нужны, но секцию читают при
		// старте -- отдаём умолчания, а не нули.
		snap.roster = sourceDefaults("none").Roster
	}

	fp, err := fingerprint(dir)
	if err != nil {
		return nil, err
	}

	snap.Fingerprint = fp
	snap.Gen = s.gen.Add(1)

	return snap, nil
}

func (s *Store) readSources(dir string, snap *Snapshot) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			// Поколение без единого источника законно: все профили off.
			return nil
		}

		return fmt.Errorf("sources: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()

		raw, err := os.ReadFile(filepath.Join(dir, name, sourceFile))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return fmt.Errorf("sources: %w", err)
		}

		src, err := ParseSource(name, raw)
		if err != nil {
			return err
		}

		if err := s.attachUsers(src, filepath.Join(dir, name)); err != nil {
			return err
		}

		if err := attachLoginPage(src, filepath.Join(dir, name)); err != nil {
			return err
		}

		if err := src.Validate(); err != nil {
			return fmt.Errorf("source %s: %w", name, err)
		}

		if err := attachJWTKey(src, filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("source %s: %w", name, err)
		}

		/*
		 * Форму обслуживает HTTP-процесс по login.uri, и у неё ровно один
		 * хозяин. У внешних провайдеров формы нет: их login.uri -- страница
		 * входа приложения, и в каталог форм она не попадает.
		 */
		if !src.External() {
			if other, dup := snap.byLogin[src.Login.URI]; dup {
				return fmt.Errorf("sources %s and %s share login.uri %q",
					other.Name, name, src.Login.URI)
			}

			snap.byLogin[src.Login.URI] = src
		}

		snap.sources[name] = src
		snap.sourceNames = append(snap.sourceNames, name)
	}

	sort.Strings(snap.sourceNames)

	return nil
}

func (s *Store) readProfiles(dir string, snap *Snapshot) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("profiles: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()

		raw, err := os.ReadFile(filepath.Join(dir, name, profileFile))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return fmt.Errorf("profiles: %w", err)
		}

		p, err := ParseProfile(name, raw)
		if err != nil {
			return err
		}

		if err := p.Validate(); err != nil {
			return fmt.Errorf("profile %s: %w", name, err)
		}

		snap.profiles[name] = p
		snap.profileNames = append(snap.profileNames, name)
	}

	sort.Strings(snap.profileNames)

	return nil
}

/*
 * attachJWTKey читает материал проверки подписи провайдера jwt: файл рядом
 * с source.yaml (PEM публичного ключа либо сырой секрет HMAC) или переменную
 * окружения. Ключ обязателен при любом alg, кроме none: источник без ключа
 * проверял бы подпись пустой строкой, и это ошибка поколения, а не
 * предупреждение.
 */
func attachJWTKey(src *Source, dir string) error {
	if src.Provider != ProviderJWT || src.Providers.JWT == nil {
		return nil
	}

	j := src.Providers.JWT

	switch {
	case j.Verify.Alg == JWTAlgNone:
		j.Key = nil

	case j.Verify.KeyFile != "":
		raw, err := os.ReadFile(filepath.Join(dir, j.Verify.KeyFile))
		if err != nil {
			return fmt.Errorf("providers.jwt.verify.key_file: %w", err)
		}

		if strings.HasPrefix(j.Verify.Alg, "HS") {
			raw = []byte(strings.TrimRight(string(raw), "\r\n"))
		}

		if len(raw) == 0 {
			return fmt.Errorf("providers.jwt.verify.key_file %q is empty", j.Verify.KeyFile)
		}

		j.Key = raw

	case j.Verify.SecretEnv != "":
		secret := os.Getenv(j.Verify.SecretEnv)
		if secret == "" {
			return fmt.Errorf("providers.jwt.verify.secret_env: %s is not set",
				j.Verify.SecretEnv)
		}

		j.Key = []byte(secret)
	}

	return nil
}

/*
 * attachLoginPage читает свою форму входа, если она приехала с поколением.
 * Нет файла -- источник работает по встроенной странице; есть, но не
 * разбирается -- ошибка снапшота, как и битый source.yaml.
 */
func attachLoginPage(src *Source, dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, loginPageFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("source %s: %w", src.Name, err)
	}

	t, err := template.New(loginPageFile).Parse(string(raw))
	if err != nil {
		return fmt.Errorf("source %s: %s: %w", src.Name, loginPageFile, err)
	}

	src.LoginPage = t

	return nil
}

func (s *Store) attachUsers(src *Source, dir string) error {
	file := src.UsersFile()
	if file == "" {
		return nil
	}

	path := file
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("source %s: %w", src.Name, err)
	}

	users, err := ParseUsers(raw)
	if err != nil {
		return fmt.Errorf("source %s: %s: %w", src.Name, file, err)
	}

	src.Users = users

	return nil
}

func fingerprint(dir string) (string, error) {
	h := sha256.New()

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(info.Size(), 10)))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(info.ModTime().UnixNano(), 10)))
		h.Write([]byte{0})

		return nil
	})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}
