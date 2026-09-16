package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/exemt/placitum-auth/internal/config"
	"github.com/exemt/placitum-shared/netinfo"
)

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
