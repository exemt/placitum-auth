/*
 * Записи правил событий в живые наборы.
 *
 * Адрес клиента пишется как есть. Анонсы (net -- эффективный, net_all -- все
 * накрывающие) и состав системы (asn) -- у кодера, синхронно, в бюджете
 * сообщения: модулю всё равно ждать инспектора, а «пусто на первом запросе»
 * -- это молча несостоявшийся бан. Запись -- одним кадром keeper: и адрес, и
 * сотни префиксов системы -- вся пачка или никак.
 *
 * Ошибка -- только от кодера: строка требует анонс или состав системы, а кодер
 * молчит либо его нет. Запись не состоится, и молча пропустить её нельзя --
 * бан, которого не было, выглядит как бан, -- поэтому вызывающий отвечает
 * error, а что делать с запросом, решает waf_exception маршрута. Так же
 * отвечают капча и остальные отправители. Отказ keeper -- строка в журнале:
 * этот запрос он не отменяет.
 */

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-shared/netinfo"
)

/*
 * Кодер и наборы -- за интерфейсами, чтобы путь записи проверялся без шины и
 * без gRPC. Боевые реализации -- netinfo.Resolver и dataset.Publisher; обе
 * nil-безопасны: nil-кодер отвечает «недоступен», nil-набор молчит.
 */
type geoWriter interface {
	Write(ctx context.Context, write, addr string) ([]string, error)
}

type listWriter interface {
	AddMany(name string, values []string, ttl time.Duration, reason string) error
}

func writeRule(ctx context.Context, geo geoWriter, lists listWriter, log *slog.Logger,
	r config.EventRule, addr, reason string) error {

	values := []string{addr}

	if netinfo.Networked(r.Write) {
		got, err := geo.Write(ctx, r.Write, addr)
		if err != nil {
			return err
		}

		if len(got) == 0 {
			log.Warn("list write skipped: coder knows nothing about the address",
				"list", r.List, "write", r.Write, "addr", addr)

			return nil
		}

		values = got
	}

	if err := lists.AddMany(r.List, values, r.TTL.D(), reason); err != nil {
		log.Warn("list write failed", "list", r.List, "write", r.Write,
			"count", len(values), "first", values[0], "error", err.Error())
	}

	return nil
}
