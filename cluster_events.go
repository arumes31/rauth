package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"rauth/internal/clusterconfig"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"rauth/internal/eventrelay"
	"rauth/internal/eventspool"
	"rauth/internal/eventstore"
	"rauth/internal/nodetelemetry"
	"rauth/internal/requestevent"
	"sync"
	"sync/atomic"
	"time"
)

type clusterEventHealth struct {
	Configured       bool                      `json:"configured"`
	NodeID           string                    `json:"node_id"`
	NodeName         string                    `json:"node_name"`
	LocalReady       bool                      `json:"local_ready"`
	CollectorReady   bool                      `json:"collector_ready"`
	Queued           int                       `json:"queued"`
	UncommittedDrops uint64                    `json:"uncommitted_drops"`
	Spool            eventspool.Status         `json:"spool"`
	Delivery         eventrelay.DeliveryStatus `json:"delivery"`
	Central          *eventstore.Status        `json:"central,omitempty"`
	CheckedAt        time.Time                 `json:"checked_at"`
}

// This actor has its own lifetime: stop it only after HTTP admission drains,
// including final policy-unavailable decisions during a listener failure.
type clusterEvents struct {
	nodeHealth  func() requestevent.NodeHealth
	stopping    bool
	material    *clusterconfig.Loaded
	spec        clusterconfig.Config
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	local       *eventspool.Store
	writer      *eventspool.Async
	collector   *eventstore.Store
	sender      *eventrelay.Sender
	client      *clustertransport.Client
	pool        *pgxpool.Pool
	earlyDrops  atomic.Uint64
	statsMu     sync.Mutex
	statsCache  map[eventstore.StatsQuery]cachedStatistics
	statsActive chan struct{}
	cached      clusterEventHealth
}

func newClusterEvents(material *clusterconfig.Loaded) *clusterEvents {
	spec := material.Config()
	if spec.Events == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &clusterEvents{material: material, spec: spec, ctx: ctx, cancel: cancel, statsCache: map[eventstore.StatsQuery]cachedStatistics{}, statsActive: make(chan struct{}, 2), cached: clusterEventHealth{Configured: true, NodeID: spec.NodeID, NodeName: spec.Events.NodeName}}
}
func (e *clusterEvents) record(event core.RequestEvent) {
	if e == nil {
		return
	}
	e.mu.RLock()
	writer := e.writer
	if writer == nil {
		e.earlyDrops.Add(1)
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()
	writer.Offer(event)
}
func (e *clusterEvents) stop() {
	if e != nil {
		e.mu.Lock()
		e.stopping = true
		e.mu.Unlock()
		e.cancel()
	}
}
func (e *clusterEvents) snapshot() clusterEventHealth {
	if e == nil {
		return clusterEventHealth{}
	}
	e.mu.RLock()
	out := e.cached
	e.mu.RUnlock()
	age := time.Since(out.CheckedAt)
	if out.CheckedAt.IsZero() || age < 0 || age > 6*time.Second {
		out.LocalReady = false
		out.CollectorReady = false
	}
	return out
}

// publishHealth timestamps the completed observation, so slow successful probes
// do not consume the snapshot freshness window before their result is visible.
func (e *clusterEvents) publishHealth(health clusterEventHealth) {
	e.mu.Lock()
	defer e.mu.Unlock()
	health.CheckedAt = time.Now().UTC()
	e.cached = health
}
func (e *clusterEvents) committer() eventrelay.Committer {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return nil
	}
	return store
}
func (e *clusterEvents) Epoch() string {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return ""
	}
	return store.Epoch()
}
func (e *clusterEvents) After(ctx context.Context, cursor uint64, node string) (eventstore.Batch, error) {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return eventstore.Batch{}, eventstore.ErrUnavailable
	}
	return store.After(ctx, cursor, node)
}
func (e *clusterEvents) run() {
	go e.localLoop()
	if e.spec.Role == clusterconfig.Control {
		go e.collectorLoop()
	}
	go e.observeLoop()
	go e.telemetryLoop()
	<-e.ctx.Done()
	e.mu.RLock()
	writer, local, pool, client := e.writer, e.local, e.pool, e.client
	e.mu.RUnlock()
	if client != nil {
		client.CloseIdleConnections()
	}
	if writer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		_ = writer.Close(ctx)
		cancel()
	}
	// A stalled logging disk must not indefinitely hold application shutdown.
	// bbolt commits are already synced; a failed drain retains its dirty marker.
	if local != nil {
		go func() { _ = local.Close() }()
	}
	if pool != nil {
		go pool.Close()
	}
}
func (e *clusterEvents) wait() bool {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-e.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func (e *clusterEvents) localLoop() {
	cfg := e.spec.Events
	maxBytes := cfg.LocalMaxBytes
	if maxBytes == 0 {
		maxBytes = eventspool.LocalBytes
	}
	age := time.Duration(cfg.LocalMaxAgeSeconds) * time.Second
	if age == 0 {
		age = 24 * time.Hour
	}
	warned := false
	for e.ctx.Err() == nil {
		var local *eventspool.Store
		var err error
		if e.material.CheckEventRoot() == nil {
			ctx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
			local, err = eventspool.Open(ctx, cfg.LocalRoot, eventspool.Options{ClusterID: e.spec.ClusterID, NodeID: e.spec.NodeID, NodeName: cfg.NodeName, MaxBytes: maxBytes, MaxAge: age})
			cancel()
		} else {
			err = eventspool.ErrUnsafe
		}
		if err != nil {
			if !warned {
				slog.Warn("Local request-event buffer is unavailable")
				warned = true
			}
			if !e.wait() {
				return
			}
			continue
		}
		if e.ctx.Err() != nil {
			_ = local.Close()
			return
		}
		maintenance, cancel := context.WithTimeout(e.ctx, 2*time.Second)
		_ = local.Maintain(maintenance)
		cancel()
		writer, err := eventspool.NewAsync(local)
		if err != nil {
			_ = local.Close()
			if !e.wait() {
				return
			}
			continue
		}
		client, err := e.material.ControllerClientWithTimeouts(eventrelay.DeliveryTimeout, eventrelay.DeliveryTimeout-time.Second)
		if err != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = writer.Close(ctx)
			cancel()
			_ = local.Close()
			if !e.wait() {
				return
			}
			continue
		}
		sender, err := eventrelay.NewSender(local, client, e.spec.Controller.Endpoint)
		if err != nil {
			client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = writer.Close(ctx)
			cancel()
			_ = local.Close()
			if !e.wait() {
				return
			}
			continue
		}
		e.mu.Lock()
		if e.stopping {
			e.mu.Unlock()
			client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = writer.Close(ctx)
			cancel()
			go func() { _ = local.Close() }()
			return
		}
		e.local = local
		e.writer = writer
		e.client = client
		e.sender = sender
		early := e.earlyDrops.Swap(0)
		e.mu.Unlock()
		writer.NoteDropped(early)
		if warned {
			slog.Info("Local request-event buffer recovered")
		}
		_ = sender.Run(e.ctx)
		return
	}
}
func (e *clusterEvents) collectorLoop() {
	config, err := pgxpool.ParseConfig(e.material.DatabaseURL("events"))
	if err != nil {
		slog.Warn("Central event database configuration is unavailable")
		return
	}
	config.MaxConns = 3
	config.MinConns = 0
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(e.ctx, config)
	if err != nil {
		return
	}
	e.mu.Lock()
	if e.stopping {
		e.mu.Unlock()
		pool.Close()
		return
	}
	e.pool = pool
	e.mu.Unlock()
	maxBytes := e.spec.Events.CentralMaxBytes
	if maxBytes == 0 {
		maxBytes = eventstore.CentralBytes
	}
	age := time.Duration(e.spec.Events.CentralMaxAgeSeconds) * time.Second
	if age == 0 {
		age = 7 * 24 * time.Hour
	}
	warned := false
	for e.ctx.Err() == nil {
		ctx, cancel := context.WithTimeout(e.ctx, eventstore.OpenTimeout)
		store, err := eventstore.Open(ctx, pool, eventstore.Options{ClusterID: e.spec.ClusterID, MaxBytes: maxBytes, MaxAge: age})
		cancel()
		if err != nil {
			if !warned {
				slog.Warn("Central request-event collector is unavailable")
				warned = true
			}
			if !e.wait() {
				return
			}
			continue
		}
		if e.ctx.Err() != nil {
			_ = store.Close()
			return
		}
		e.mu.Lock()
		if e.stopping {
			e.mu.Unlock()
			_ = store.Close()
			return
		}
		e.collector = store
		e.mu.Unlock()
		if warned {
			slog.Info("Central request-event collector recovered")
		}
		maintenance := time.NewTicker(time.Minute)
		check := time.NewTicker(2 * time.Second)
		active := true
		for active && e.ctx.Err() == nil {
			select {
			case <-e.ctx.Done():
				active = false
			case <-maintenance.C:
				ctx, cancel := context.WithTimeout(e.ctx, eventrelay.IngestTimeout)
				err = store.Maintain(ctx)
				cancel()
				if err != nil {
					active = false
				}
			case <-check.C:
				ctx, cancel := context.WithTimeout(e.ctx, eventstore.HealthTimeout)
				_, err = store.Status(ctx)
				cancel()
				if err != nil {
					active = false
				}
			}
		}
		maintenance.Stop()
		check.Stop()
		e.mu.Lock()
		if e.collector == store {
			e.collector = nil
		}
		e.mu.Unlock()
		e.statsMu.Lock()
		e.statsCache = map[eventstore.StatsQuery]cachedStatistics{}
		e.statsMu.Unlock()
		_ = store.Close()
		if e.ctx.Err() != nil || !e.wait() {
			return
		}
		warned = true

	}
}
func (e *clusterEvents) observeLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for e.ctx.Err() == nil {
		e.mu.RLock()
		local, writer, sender, collector := e.local, e.writer, e.sender, e.collector
		e.mu.RUnlock()
		health := clusterEventHealth{Configured: true, NodeID: e.spec.NodeID, NodeName: e.spec.Events.NodeName, UncommittedDrops: e.earlyDrops.Load()}
		if local != nil && writer != nil {
			ctx, cancel := context.WithTimeout(e.ctx, time.Second)
			status, err := local.Status(ctx)
			cancel()
			health.Spool = status
			health.LocalReady = err == nil && writer.Available()
			health.Queued = writer.Queued()
			health.UncommittedDrops += writer.UncommittedDrops()
		}
		if sender != nil {
			health.Delivery = sender.Status()
		}
		if collector != nil {
			ctx, cancel := context.WithTimeout(e.ctx, eventstore.HealthTimeout)
			status, err := collector.Status(ctx)
			cancel()
			health.CollectorReady = err == nil
			if err == nil {
				health.Central = &status
			}
		}
		e.publishHealth(health)
		select {
		case <-e.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (e *clusterEvents) telemetryLoop() {
	collector := nodetelemetry.New(nil)
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	sampleNumber := 0
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-tick.C:
			e.mu.RLock()
			writer := e.writer
			e.mu.RUnlock()
			if writer != nil {
				snapshot := collector.Capture()
				if e.nodeHealth != nil {
					h := e.nodeHealth()
					state := e.snapshot()
					h.LocalReady = state.LocalReady
					h.Pending = state.Spool.Pending
					h.DiskBytes = state.Spool.DiskBytes
					h.Oldest = state.Spool.Oldest
					h.Dropped = state.Spool.Dropped
					h.UncleanRestarts = state.Spool.UncleanRestarts
					h.DeliveryReady = state.Delivery.Available
					h.LastDelivered = state.Delivery.LastSuccess
					snapshot.Health = &h
				}
				writer.OfferMetrics(snapshot)
				sampleNumber++
				if sampleNumber%6 == 1 {
					for _, snapshot := range collector.Diagnostics() {
						writer.OfferMetrics(snapshot)
					}
				}
			}
		}
	}
}

type cachedStatistics struct {
	at   time.Time
	data eventstore.StatsSnapshot
}

func (e *clusterEvents) Statistics(ctx context.Context, q eventstore.StatsQuery) (eventstore.StatsSnapshot, error) {
	if _, _, err := q.Window(time.Now()); err != nil {
		return eventstore.StatsSnapshot{}, err
	}
	e.mu.RLock()
	available := e.collector != nil
	e.mu.RUnlock()
	if !available {
		return eventstore.StatsSnapshot{}, eventstore.ErrUnavailable
	}
	e.statsMu.Lock()
	cached, ok := e.statsCache[q]
	e.statsMu.Unlock()
	ttl := time.Second
	if q.Range == "24h" {
		ttl = 10 * time.Second
	}
	if q.Range == "7d" {
		ttl = 30 * time.Second
	}
	if ok && time.Since(cached.at) >= 0 && time.Since(cached.at) < ttl {
		return cached.data, nil
	}
	select {
	case e.statsActive <- struct{}{}:
		defer func() { <-e.statsActive }()
	default:
		return eventstore.StatsSnapshot{}, eventstore.ErrUnavailable
	}
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return eventstore.StatsSnapshot{}, eventstore.ErrUnavailable
	}
	data, err := store.Statistics(ctx, q)
	if err == nil {
		e.statsMu.Lock()
		if len(e.statsCache) >= 32 {
			e.statsCache = map[eventstore.StatsQuery]cachedStatistics{}
		}
		e.statsCache[q] = cachedStatistics{time.Now(), data}
		e.statsMu.Unlock()
	}
	return data, err
}
func (e *clusterEvents) Decisions(ctx context.Context, q eventstore.StatsQuery) ([]requestevent.Event, error) {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return nil, eventstore.ErrUnavailable
	}
	return store.Decisions(ctx, q)
}
func (e *clusterEvents) Diagnostics(ctx context.Context, node string) (eventstore.Diagnostics, error) {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return eventstore.Diagnostics{}, eventstore.ErrUnavailable
	}
	return store.Diagnostics(ctx, node)
}

func (e *clusterEvents) FeedStart(ctx context.Context, node string, limit int) (uint64, error) {
	e.mu.RLock()
	store := e.collector
	e.mu.RUnlock()
	if store == nil {
		return 0, eventstore.ErrUnavailable
	}
	return store.FeedStart(ctx, node, limit)
}
