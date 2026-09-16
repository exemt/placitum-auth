package roster

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type Roster interface {
	Burn(ctx context.Context, kind, id string, ttl time.Duration) (bool, error)

	Fail(ctx context.Context, scope string, window time.Duration) (int, error)
	Clear(ctx context.Context, scope string) error
	Lock(ctx context.Context, scope string, d time.Duration) error
	LockedFor(ctx context.Context, scope string) (time.Duration, error)

	Close() error
}

type Redis struct {
	client  *redis.Client
	prefix  string
	timeout time.Duration
}

func NewRedis(url, prefix string, timeout time.Duration) (*Redis, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}

	opt.ReadTimeout = timeout
	opt.WriteTimeout = timeout
	opt.DialTimeout = timeout

	return &Redis{client: redis.NewClient(opt), prefix: prefix, timeout: timeout}, nil
}

func (r *Redis) key(parts ...string) string {
	out := r.prefix

	for i, p := range parts {
		if i > 0 {
			out += ":"
		}

		out += p
	}

	return out
}

func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	return r.client.Ping(ctx).Err()
}

func (r *Redis) Burn(ctx context.Context, kind, id string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.SetNX(ctx, r.key(kind, id), 1, ttl).Result()
}

func (r *Redis) Fail(ctx context.Context, scope string, window time.Duration) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	key := r.key("fail", scope)

	pipe := r.client.TxPipeline()
	inc := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, err
	}

	return int(inc.Val()), nil
}

func (r *Redis) Clear(ctx context.Context, scope string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	return r.client.Del(ctx, r.key("fail", scope), r.key("lock", scope)).Err()
}

func (r *Redis) Lock(ctx context.Context, scope string, d time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.key("lock", scope), 1, d)
	pipe.Del(ctx, r.key("fail", scope))

	_, err := pipe.Exec(ctx)

	return err
}

func (r *Redis) LockedFor(ctx context.Context, scope string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ttl, err := r.client.TTL(ctx, r.key("lock", scope)).Result()
	if err != nil {
		return 0, err
	}

	if ttl <= 0 {
		return 0, nil
	}

	return ttl, nil
}

func (r *Redis) Close() error { return r.client.Close() }

type Memory struct {
	mu     sync.Mutex
	burned map[string]time.Time
	fails  map[string]counter
	locks  map[string]time.Time
}

type counter struct {
	n     int
	until time.Time
}

func NewMemory() *Memory {
	return &Memory{
		burned: map[string]time.Time{},
		fails:  map[string]counter{},
		locks:  map[string]time.Time{},
	}
}

func (m *Memory) Burn(_ context.Context, kind, id string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := kind + ":" + id
	now := time.Now()

	if until, ok := m.burned[key]; ok && now.Before(until) {
		return false, nil
	}

	m.burned[key] = now.Add(ttl)

	return true, nil
}

func (m *Memory) Fail(_ context.Context, scope string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	c := m.fails[scope]

	if now.After(c.until) {
		c = counter{}
	}

	c.n++
	c.until = now.Add(window)
	m.fails[scope] = c

	return c.n, nil
}

func (m *Memory) Clear(_ context.Context, scope string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.fails, scope)
	delete(m.locks, scope)

	return nil
}

func (m *Memory) Lock(_ context.Context, scope string, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.locks[scope] = time.Now().Add(d)
	delete(m.fails, scope)

	return nil
}

func (m *Memory) LockedFor(_ context.Context, scope string) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	until, ok := m.locks[scope]
	if !ok {
		return 0, nil
	}

	left := time.Until(until)
	if left <= 0 {
		delete(m.locks, scope)

		return 0, nil
	}

	return left, nil
}

func (m *Memory) Close() error { return nil }
