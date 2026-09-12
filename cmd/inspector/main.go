/*
 * Точка входа инспектора калитки.
 *
 * Профили, ключ подписи и обменник проверяются до подписки: калитка, которая
 * молча уводит всех на форму из-за опечатки в каталоге, хуже не
 * запустившейся. Дальше профили перечитываются сами.
 */

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/exemt/placitum-auth/internal/audit"
	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-auth/internal/dataset"
	"github.com/exemt/placitum-auth/internal/desired"
	"github.com/exemt/placitum-shared/flow"
	"github.com/exemt/placitum-auth/internal/livelist"
	"github.com/exemt/placitum-auth/internal/logsink"
	"github.com/exemt/placitum-shared/netinfo"
	"github.com/exemt/placitum-shared/pulse"
	"github.com/exemt/placitum-auth/internal/queue"
	"github.com/exemt/placitum-auth/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(config.RoleInspector)
	if err != nil {
		return err
	}

	/*
	 * Журнал процесса уезжает в waf.log той же пачкой, что и строки nginx:
	 * контур один, и искать причину отказа по трём десяткам docker-логов
	 * незачем. Приёмник поднимается раньше шины -- строки о том, как читался
	 * конфиг, копятся и уезжают первой же пачкой. Копия, не перенос: stdout
	 * остаётся на месте.
	 */
	var (
		logs  *logsink.Sink
		logIO *flow.Counter
	)

	if config.LogShip() {
		logIO = flow.New()
		logs = logsink.New(config.LogWriter(cfg.Name), cfg.Name, logIO)

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
	log.Info("profiles loaded",
		"profiles", snap.Names(),
		"gen", snap.Gen,
		"fingerprint", snap.Fingerprint,
	)

	/*
	 * Обменник обязателен и проверяется на старте. Заголовки едут локатором, и
	 * инспектор без доступа к хранилищу не увидит ни одной cookie -- то есть
	 * уведёт на форму даже тех, кто уже вошёл.
	 */
	hot, err := store.NewRedis(cfg.RedisURL, cfg.StoreTimeout)
	if err != nil {
		return err
	}

	defer hot.Close()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()

	if err := hot.Ping(ctx); err != nil {
		return err
	}

	nc, err := nats.Connect(joined(cfg.Servers),
		nats.Name("waf-inspector-"+cfg.Name),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(500*time.Millisecond),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Warn("bus disconnected", "error", errText(err))
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("bus reconnected", "server", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return err
	}

	defer nc.Close()

	if err := audit.Ensure(nc); err != nil {
		log.Warn("audit stream", "error", err.Error())
	}

	/*
	 * Поток журнала заводит тот писатель, который пришёл первым: на контуре,
	 * где ни одна нода ещё не поднялась, им оказывается инспектор. Публикация
	 * в несуществующий поток -- тишина, а не ошибка.
	 */
	if logs != nil {
		if err := logsink.Ensure(nc); err != nil {
			log.Warn("log stream", "error", err.Error())
		}

		logs.Attach(nc)
		log.Info("log stream", "stream", logsink.Stream,
			"subject", logsink.Subject(logs.Writer()))
	}

	/*
	 * Поколение из KV. Bootstrap до подписки: рестарт, не успевший догнать
	 * watch, не должен откатываться на профили из образа и пускать людей по
	 * позавчерашнему набору факторов.
	 */
	var applied *desired.Applied

	if cfg.DataDir != "" {
		desired.Bootstrap(profiles, cfg.DataDir, log)

		applied, err = desired.Watch(ctx, nc, profiles, cfg.DataDir, level, log)
		if err != nil {
			log.Warn("desired watch failed", "error", err.Error())
		}
	}

	/*
	 * Зеркало активных списков -- истина калитки. Пакеты и снапшоты оно
	 * читает из внутреннего Redis контура. Подписки сверяются со снимком
	 * профилей по шагу: источник со списком может появиться из KV уже после
	 * старта.
	 */
	config.LogInternalRedis(log, cfg.InternalURL, cfg.InternalFrom)

	sets, err := livelist.OpenBlobs(cfg.InternalURL)
	if err != nil {
		return err
	}

	defer sets.Close()

	sessions := livelist.New(nc, sets, log)

	go watchLists(ctx, sessions, profiles)

	/*
	 * События аудита уезжают пачками, а не по одной на инспекцию: при четырёх
	 * инспекторах в наборе это впятеро больше сообщений, чем запросов, и
	 * партия из одного сообщения кладёт вставку у потребителя.
	 *
	 * Закрывается после пула: в очереди события уже отвеченных запросов.
	 */
	auditSink := audit.NewSink(nc, log)

	/*
	 * Кодер гео -- для правил событий, которые пишут не адрес (net, net_all,
	 * asn). Соединение ленивое: профиль без таких строк кодер не трогает ни
	 * разу. Пусто в окружении -- кодера нет, такие строки отвечают error.
	 */
	var resolver *netinfo.Resolver

	if cfg.GeoAddr != "" {
		var rerr error

		resolver, rerr = netinfo.New(cfg.GeoAddr, cfg.GeoTimeout, cfg.GeoNegMax, log)
		if rerr != nil {
			return fmt.Errorf("geo resolver: %w", rerr)
		}

		defer resolver.Close()
	}

	h := &handler{cfg: cfg, log: log, nc: nc,
		audit: auditSink, profiles: profiles, store: hot,
		sessions: sessions,
		// Подглядывание входа приложения пишет в список от имени инспектора.
		lists: dataset.New(nc, cfg.Name), resolver: resolver}

	if cfg.HTTPURL != "" {
		h.forms = newFormFetcher(cfg.HTTPURL)
	} else {
		log.Warn("WAF_AUTH_HTTP_URL is empty: profiles with gate.inline answer " +
			"with a redirect")
	}
	pool := queue.New(cfg.Workers, cfg.QueueDepth, cfg.ReserveMS, cfg.MinBudgetMS,
		cfg.QueueFull, h.evaluate)
	h.pool = pool

	sub, err := nc.QueueSubscribe(cfg.Subject, cfg.Queue, h.receive)
	if err != nil {
		return err
	}

	// Забираем с шины сразу. pending — запас на полёт в колбэк, не очередь:
	// прокисшие выкидываем из pool, слот занимает свежий запрос.
	if err := sub.SetPendingLimits(cfg.QueueDepth+cfg.Workers+2, 4*1024*1024); err != nil {
		return err
	}

	log.Info("connected",
		"server", nc.ConnectedUrl(),
		"subject", cfg.Subject,
		"queue", cfg.Queue,
		"inspector", cfg.Name,
		"workers", cfg.Workers,
		"queue_max", cfg.QueueDepth,
		"queue_full", cfg.QueueFull,
		"conf", cfg.ConfPath,
	)

	go profiles.Watch(ctx, cfg.ReloadEvery)

	inspectorID := pulse.NewID()
	stopBeat := startHeartbeat(nc, cfg, inspectorID, pool, profiles, applied, logIO, log)
	defer stopBeat()

	waitForSignal(profiles, log)
	stop()

	if err := sub.Drain(); err != nil {
		log.Warn("drain failed", "error", err.Error())
	}

	pool.Close()
	auditSink.Close()

	log.Info("drained",
		"accepted", pool.Accepted.Load(),
		"shed", pool.Shed.Load(),
		"expired", pool.Expired.Load(),
	)

	return nil
}

/*
 * watchLists держит зеркало подписанным на списки всех источников снимка.
 * Ensure идемпотентен, поэтому сверка по шагу ничего не стоит.
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

func startHeartbeat(
	nc *nats.Conn,
	cfg *config.Config,
	id string,
	pool *queue.Pool,
	profiles *config.Store,
	applied *desired.Applied,
	logIO *flow.Counter,
	log *slog.Logger,
) func() {
	subject := pulse.Subject(cfg.Name, id)
	log.Info("heartbeat on", "subject", subject, "id", id, "every", cfg.HeartbeatEvery.String())

	beat := func() {
		work := &pulse.Work{
			Workers:    cfg.Workers,
			QueueDepth: cfg.QueueDepth,
			Queued:     pool.Queued(),
			Accepted:   pool.Accepted.Load(),
			Shed:       pool.Shed.Load(),
			Expired:    pool.Expired.Load(),
		}
		io := map[string]flow.Flow{"inspect": pool.IO()}

		// Канал журнала -- там же, где темп инспекции: потерянная строка
		// видна ошибкой канала, и это единственное место, где её видно.
		// Сам приёмник о своих потерях молчит по построению.
		if logIO != nil {
			io["log"] = logIO.Snapshot()
		}
		msg := pulse.Build(id, cfg.Name, cfg.Subject, cfg.Queue, work, io)

		if snap := profiles.Current(); snap != nil {
			msg.Rev = int(snap.Gen)
			msg.ConfigHash = snap.Fingerprint
			msg.Apply = desired.ApplyOK
			msg.Profiles = snap.Names()
		}

		/*
		 * Поколение контроллера перекрывает локальный отпечаток: сходимость
		 * флота считают по нему, и отпечаток каталога, который контроллер
		 * повторить не может, для этого не годится.
		 */
		if hash, rev, apply, names := applied.Snapshot(); apply != "" {
			msg.ConfigHash = hash
			msg.Rev = rev
			msg.Apply = apply

			if len(names) > 0 {
				msg.Profiles = names
			}
		}

		if err := pulse.Publish(nc, msg); err != nil {
			log.Warn("heartbeat failed", "error", err.Error())
		}
	}

	beat()
	tick := time.NewTicker(cfg.HeartbeatEvery)

	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				beat()
			}
		}
	}()

	return func() {
		tick.Stop()
		close(done)
	}
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

		log.Info("draining", "signal", sig.String())

		return
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

func errText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
