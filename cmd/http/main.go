/*
 * Точка входа сервиса формы входа.
 *
 * Живёт за location с waf off и никогда не отвечает на шину. Бюджет здесь
 * другой: bcrypt считается десятки миллисекунд по построению, bind к
 * контроллеру домена уходит в сеть. Поэтому это отдельный контейнер, а не
 * ветка в инспекторе.
 */

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/dataset"
	"github.com/exemt/placitum-auth/internal/desired"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/logsink"
	"github.com/exemt/placitum-auth/internal/provider"
	"github.com/exemt/placitum-auth/internal/roster"
	"github.com/exemt/placitum-auth/internal/secrets"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.RoleHTTP)
	if err != nil {
		return err
	}

	/*
	 * Журнал калитки уезжает в waf.log тем же каналом, что и журнал
	 * инспектора: отказ провайдера видно в форме входа, а не на шине, и
	 * искать его по docker-логам отдельного контейнера незачем. Шины у
	 * калитки может не быть вовсе -- тогда остаётся один stdout.
	 */
	var logs *logsink.Sink

	if config.LogShip() {
		logs = logsink.New(config.LogWriter(cfg.Name), cfg.Name+"-http", nil)

		defer logs.Close()
	}

	/*
	 * Порог журнала живой: поколение из KV переставляет его без рестарта
	 * (internal/loglevel). Переменная окружения задаёт стартовое значение.
	 */
	level := new(slog.LevelVar)
	level.Set(cfg.LogLevel)

	log := slog.New(slog.NewJSONHandler(logs.Tee(os.Stdout),
		&slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	profiles, err := config.LoadProfiles(cfg.ProfilesDir, log)
	if err != nil {
		return err
	}

	snap := profiles.Current()

	pages, err := loadPages(cfg.WebDir)
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	rev, err := openRoster(ctx, cfg, snap, log)
	if err != nil {
		return err
	}

	defer rev.Close()

	list, nc, closeBus, err := openBus(cfg, snap, log)
	if err != nil {
		return err
	}

	defer closeBus()

	/*
	 * Публикация только при живой шине: калитка поднимается и без неё, и
	 * тогда журнал остаётся там же, где был.
	 */
	if logs != nil && nc != nil {
		if err := logsink.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logsink.Stream,
			"subject", logsink.Subject(logs.Writer()))
	}

	/*
	 * Ключ контура нужен только форме и только ради ссылок store: в профиле,
	 * приехавшем из контроллера. Нет ключа -- профиль обязан обходиться
	 * переменными окружения, и это проверяется при его загрузке.
	 */
	sec, err := secrets.New(cfg.ControllerURL, cfg.Scope, cfg.ContourKeyFile,
		10*time.Second)
	if err != nil {
		return err
	}

	var keeper provider.Secrets
	if sec != nil {
		keeper = sec

		log.Info("contour key loaded", "controller", cfg.ControllerURL, "scope", cfg.Scope)
	}

	/*
	 * Зеркало активных списков. Форме оно нужно там же, где инспектору:
	 * продление и стыкованный источник обязаны видеть, что сессию уже
	 * завершили, -- иначе выход держал бы всё, кроме продления.
	 */
	var sessions *livelist.Mirror

	if nc != nil {
		var sets livelist.Blobs

		if cfg.InternalURL != "" {
			opened, err := livelist.OpenBlobs(cfg.InternalURL)
			if err != nil {
				return err
			}

			defer opened.Close()
			sets = opened
		}

		sessions = livelist.New(nc, sets, log)

		go watchLists(ctx, sessions, profiles)
	}

	srv := &server{
		cfg:      cfg,
		log:      log,
		profiles: profiles,
		roster:   rev,
		pages:    pages,
		list:     list,
		sessions: sessions,
		secrets:  keeper,
	}

	// Поколение из KV: форма обязана видеть те же профили, что инспектор,
	// иначе вход шёл бы по одному набору факторов, а допуск -- по другому.
	if nc != nil && cfg.DataDir != "" {
		desired.Bootstrap(profiles, cfg.DataDir, log)

		if _, err := desired.Watch(ctx, nc, profiles, cfg.DataDir, level, log); err != nil {
			log.Warn("desired watch failed", "error", err.Error())
		}
	}

	go profiles.Watch(ctx, cfg.ReloadEvery)

	http.Handle("/", srv)

	/*
	 * Таймауты явные: форма стоит первой перед приложением, и медленный
	 * клиент не должен занимать её воркер дольше, чем занял бы приложение.
	 * WriteTimeout с запасом на bind к каталогу.
	 */
	hs := &http.Server{
		Addr:              cfg.Listen,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Info("listening",
			"addr", cfg.Listen,
			"profiles", snap.Names(),
			"roster", snap.Roster().Store,
		)

		if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen failed", "error", err.Error())
			stop()
		}
	}()

	waitForSignal(profiles, log)
	stop()

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return hs.Shutdown(shutdown)
}

/*
 * openBus поднимает связь с шиной только тогда, когда она нужна: список --
 * необязательная оптимизация, и профиль без него не должен требовать NATS от
 * процесса, который иначе к шине не ходит вовсе.
 */
func openBus(cfg *config.Config, snap *config.Snapshot, log *slog.Logger) (
	*dataset.Publisher, *nats.Conn, func(), error) {

	names := map[string]bool{}

	for _, src := range snap.Sources() {
		if src.List.Enabled() {
			names[src.List.Sessions] = true
		}
	}

	/*
	 * Связь нужна двум вещам: активному списку и слежению за поколением. Ни
	 * той ни другой нет -- к шине не ходим вовсе.
	 */
	if len(names) == 0 && cfg.DataDir == "" {
		return nil, nil, func() {}, nil
	}

	if len(cfg.Servers) == 0 {
		if len(names) > 0 {
			return nil, nil, nil,
				errors.New("NATS_URL is empty and a profile declares list.sessions")
		}

		return nil, nil, func() {}, nil
	}

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-auth-http"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	for name := range names {
		log.Info("session list on", "set", name)
	}

	/*
	 * Публикатор есть всегда, когда есть шина: список может появиться в
	 * профиле из KV уже после старта, и решать по bootstrap-каталогу, будет
	 * ли он нужен, значило бы молча не публиковать.
	 */
	return dataset.New(nc, cfg.Name), nc, nc.Close, nil
}

/*
 * watchLists держит зеркало подписанным на списки всех источников. Снимок
 * профилей меняется на лету, поэтому подписки сверяются с ним по шагу;
 * Ensure идемпотентен, и лишний вызов ничего не стоит.
 */
func watchLists(ctx context.Context, m *livelist.Mirror, profiles *config.Store) {
	defer m.Close()

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		for _, src := range profiles.Current().Sources() {
			if src.List.Enabled() {
				m.Ensure(src.List.Sessions)
			}
		}

		select {
		case <-ctx.Done():
			return

		case <-tick.C:
		}
	}
}

func joined(servers []string) string {
	out := ""

	for i, s := range servers {
		if i > 0 {
			out += ","
		}

		out += s
	}

	return out
}

func openRoster(ctx context.Context, cfg *config.Config, snap *config.Snapshot,
	log *slog.Logger) (roster.Roster, error) {

	rc := snap.Roster()

	if rc.Store == config.RosterMemory {
		log.Warn("roster is in-process: nonce and lockout do not cross replicas")

		return roster.NewMemory(), nil
	}

	// Роастер живёт во внутреннем Redis контура (internal блока redis в
	// inspector.conf или REDIS_INTERNAL_URL): обменник HTTP-процессу не нужен,
	// заголовки запроса он не читает.
	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)
	if cfg.InternalURL == "" {
		return nil, errors.New("REDIS_INTERNAL_URL is empty and roster.store is redis")
	}

	r, err := roster.NewRedis(cfg.InternalURL, rc.Prefix, cfg.StoreTimeout)
	if err != nil {
		return nil, err
	}

	if err := r.Ping(ctx); err != nil {
		return nil, err
	}

	return r, nil
}

func waitForSignal(profiles *config.Store, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-ch

		if sig == syscall.SIGHUP {
			if _, err := profiles.Reload(); err != nil {
				log.Warn("sighup reload failed", "error", err.Error())
			}

			continue
		}

		log.Info("shutting down", "signal", sig.String())

		return
	}
}
