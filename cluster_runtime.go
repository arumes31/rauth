package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"rauth/internal/clusterconfig"
	"rauth/internal/clusterpolicy"
	"rauth/internal/clusterregistry"
	"rauth/internal/clusterstate"
	"rauth/internal/clusterstatus"
	"rauth/internal/clustertransport"
	"rauth/internal/clusterworker"
	"rauth/internal/core"
	"rauth/internal/eventrelay"
	"rauth/internal/requestevent"
	"strconv"
	"sync"
	"time"
)

var errClusterRuntime = errors.New("cluster runtime configuration or authority is unavailable")

type privateRPCClient interface {
	Do(*http.Request) (*http.Response, error)
}
type clusterRuntime struct {
	publicConfig  *core.Config
	material      *clusterconfig.Loaded
	spec          clusterconfig.Config
	worker        *clusterworker.Worker[*core.PolicySnapshot]
	registry      *clusterregistry.Reader
	self          clustertransport.Peer
	publisher     *core.ControllerPolicyPublisher
	client        *clustertransport.Client
	relayClient   privateRPCClient
	pools         []*pgxpool.Pool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
	notices       *policyNoticeHub
	policyState   *clusterPolicyState
	health        *clusterHealth
	events        *clusterEvents
	eventRegistry *clusterregistry.Reader
}

// loadClusterBootstrap runs before database/authority initialization. Legacy
// startup remains unchanged when the explicit host-file opt-in is absent.
func loadClusterBootstrap(cfg *core.Config) (*clusterconfig.Loaded, error) {
	return core.LoadClusterBootstrap(cfg)
}
func newClusterRuntime(parent context.Context, cfg *core.Config, material *clusterconfig.Loaded) (*clusterRuntime, error) {
	if material == nil || parent == nil || cfg == nil || cfg.ClusterConfigFile == "" {
		return nil, errClusterRuntime
	}
	spec := material.Config()
	if material.CheckCacheRoot() != nil {
		return nil, errClusterRuntime
	}
	options, err := core.WorkerPolicyOptionsForConfig(spec.NodeID, cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	r := &clusterRuntime{publicConfig: cfg, material: material, spec: spec, ctx: ctx, cancel: cancel, notices: newPolicyNoticeHub()}
	ok := false
	defer func() {
		if !ok {
			r.Close()
		}
	}()
	openPool := func(name string, maxConns int32) (*pgxpool.Pool, error) {
		config, e := pgxpool.ParseConfig(material.DatabaseURL(name))
		if e != nil {
			return nil, errClusterRuntime
		}
		config.MaxConns = maxConns
		config.MinConns = 0
		config.ConnConfig.ConnectTimeout = 3 * time.Second
		pool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			return nil, errClusterRuntime
		}
		r.pools = append(r.pools, pool)
		return pool, nil
	}
	heads, err := openPool("head", 1)
	if err != nil {
		return nil, err
	}
	blobs, err := openPool("payload", 2)
	if err != nil {
		return nil, err
	}
	registryPool, err := openPool("registry", 2)
	if err != nil {
		return nil, err
	}
	r.registry, err = clusterregistry.NewReader(registryPool, spec.ClusterID)
	if err != nil {
		return nil, errClusterRuntime
	}
	serverTLS, err := material.ServerTLS()
	if err != nil {
		return nil, errClusterRuntime
	}
	leaf, err := x509.ParseCertificate(serverTLS.Certificates[0].Certificate[0])
	if err != nil {
		return nil, errClusterRuntime
	}
	r.self = clustertransport.Peer{ClusterID: spec.ClusterID, NodeID: spec.NodeID, SPKI: sha256.Sum256(leaf.RawSubjectPublicKeyInfo), ExpiresAt: leaf.NotAfter, ServiceIP: netip.MustParseAddr(spec.ServiceIP)}
	enrolled, err := r.registry.Lookup(ctx, spec.NodeID)
	if err != nil || enrolled.Role != spec.Role || r.registry.Authorize(ctx, r.self, clustertransport.PolicyRead) != nil {
		return nil, errClusterRuntime
	}
	r.client, err = material.ControllerClient()
	if err != nil {
		return nil, errClusterRuntime
	}
	r.relayClient = r.client
	r.health = newClusterHealth(core.CheckAuthenticationAuthority, func(ctx context.Context) error { return r.registry.Authorize(ctx, r.self, clustertransport.PolicyRead) })
	source, err := clusterstate.NewReader(heads, blobs, material.Verifier())
	if err != nil {
		return nil, errClusterRuntime
	}
	factory := func() clusterworker.Compiler[*core.PolicySnapshot] {
		compiler, _ := core.NewWorkerPolicyCompiler(options)
		return compiler
	}
	r.worker, err = clusterworker.NewWithContext(ctx, spec.CacheRoot, material.Verifier(), source, factory, clusterpolicy.DefaultLease)
	if err != nil {
		return nil, errClusterRuntime
	}
	if spec.Role == clusterconfig.Control {
		profiles := map[string]core.WorkerPolicyNodeProfile{}
		requireGeo := options.RequireGeoIP
		for id, profile := range material.Profiles() {
			profiles[id] = core.WorkerPolicyNodeProfile{SecurityFingerprint: profile.SecurityFingerprint, RequireGeoIP: profile.RequireGeoIP}
			requireGeo = requireGeo || profile.RequireGeoIP
		}
		if profiles[spec.NodeID].SecurityFingerprint != options.SecurityFingerprint || (requireGeo && spec.GeoIPFile == "") {
			return nil, errClusterRuntime
		}
		sourcePool, e := openPool("source", 1)
		if e != nil {
			return nil, e
		}
		writePool, e := openPool("publisher", 1)
		if e != nil {
			return nil, e
		}
		statusPool, e := openPool("publisher", 1)
		if e != nil {
			return nil, e
		}
		receipts, e := clusterstatus.New(statusPool, spec.ClusterID)
		if e != nil {
			return nil, errClusterRuntime
		}
		assigned := []string{}
		for id := range profiles {
			assigned = append(assigned, id)
		}
		r.policyState = &clusterPolicyState{store: receipts, assigned: assigned}
		keyID, key := material.Signer()
		var geo func(context.Context) (io.ReadCloser, error)
		if spec.GeoIPFile != "" {
			geo = material.OpenGeoIP
		}
		r.publisher, e = core.NewControllerPolicyPublisher(writePool, sourcePool, heads, blobs, material.Verifier(), keyID, key, core.WorkerPolicyCaptureOptions{NodeID: spec.NodeID, Config: cfg, Profiles: profiles, OpenGeoIP: geo})
		if e != nil {
			return nil, errClusterRuntime
		}
	}
	r.events = newClusterEvents(material)
	if r.events != nil {
		r.events.nodeHealth = func() requestevent.NodeHealth {
			p := r.worker.Status().Policy
			auth, enrollment := r.health.status()
			return requestevent.NodeHealth{Ready: p.Ready && auth && enrollment, AuthReady: auth, EnrollmentReady: enrollment, PolicyReady: p.Ready, Applied: p.Applied.Revision, Desired: p.Desired.Revision, LeaseExpiresAt: p.LeaseExpiresAt}
		}
	}
	if r.events != nil && spec.Role == clusterconfig.Control {
		eventsRegistryPool, e := openPool("registry", 1)
		if e != nil {
			return nil, e
		}
		r.eventRegistry, e = clusterregistry.NewReader(eventsRegistryPool, spec.ClusterID)
		if e != nil {
			return nil, errClusterRuntime
		}
	}
	ok = true
	return r, nil
}
func (r *clusterRuntime) Start() {
	if r.events != nil {
		r.wg.Go(r.events.run)
	}
	r.wg.Go(func() { r.health.run(r.ctx) })
	r.wg.Go(func() { _ = r.worker.Run(r.ctx) })
	r.wg.Go(r.reportPolicyStatus)
	if r.publisher == nil {
		r.wg.Go(r.followPolicyNotices)
	}
	if r.publisher != nil {
		r.wg.Go(func() {
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			warned := false
			for {
				publication, err := r.publisher.Reconcile(r.ctx)
				r.policyState.observed(publication, err)
				if err != nil && r.ctx.Err() == nil && !warned {
					slog.Warn("Cluster policy publication is unavailable")
					warned = true
				}
				if err == nil {
					warned = false
					r.notices.publish(publication.Identity)
					if publication.Changed {
						r.worker.Notify()
					}
				}
				select {
				case <-r.ctx.Done():
					return
				case <-tick.C:
				}
			}
		})
	}
}
func (r *clusterRuntime) Close() {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() {
		r.cancel()
		if r.events != nil {
			r.events.stop()
		}
		if r.worker != nil {
			_ = r.worker.Close()
		}
		r.wg.Wait()
		if r.client != nil {
			r.client.CloseIdleConnections()
		}
		for _, pool := range r.pools {
			pool.Close()
		}
	})
}
func (r *clusterRuntime) Health(c echo.Context) error {
	status := r.worker.Status()
	ready := status.Policy.Ready
	checks := map[string]bool{"policy": ready}
	checks["auth_state"], checks["node_enrollment"] = r.health.status()
	ready = ready && checks["auth_state"] && checks["node_enrollment"]
	code := http.StatusOK
	if !ready {
		code = http.StatusServiceUnavailable
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(code, map[string]any{"ready": ready})
}
func (r *clusterRuntime) PrivateServer(public http.Handler) (*http.Server, error) {
	gate, err := clustertransport.NewGate(r.spec.ClusterID, r.registry.Authorize)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	status, _ := gate.Protect(clustertransport.StatusRead, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		state := r.worker.Status()
		w.Header().Set("Content-Type", "application/json")
		_ = writeClusterStatus(w, r.spec.NodeID, state.Policy, r.events.snapshot())
	}))
	mux.Handle("GET /v1/status", status)
	if r.spec.Role == clusterconfig.Control {
		assigned := map[string]bool{}
		for id := range r.material.Profiles() {
			assigned[id] = true
		}
		notices, noticeErr := gate.Protect(clustertransport.PolicyRead, policyNoticeHandler(r.notices, r.registry.Authorize, assigned))
		if noticeErr != nil {
			return nil, noticeErr
		}
		mux.Handle("GET /v1/policy-notices", notices)
		if r.events != nil && r.eventRegistry != nil {
			eventGate, e := clustertransport.NewGate(r.spec.ClusterID, r.eventRegistry.Authorize)
			if e != nil {
				return nil, e
			}
			handler, e := eventGate.Protect(clustertransport.EventsWrite, eventrelay.Receiver(r.events.committer, assigned))
			if e != nil {
				return nil, e
			}
			mux.Handle("POST /v1/events", handler)
		}

		receipt, receiptErr := gate.Protect(clustertransport.PolicyRead, receiptHandler(r.policyState))
		if receiptErr != nil {
			return nil, receiptErr
		}
		mux.Handle("POST /v1/policy-receipt", receipt)
		relay, e := gate.Protect(clustertransport.AdminRelay, r.receiveAdminRelay(public))
		if e != nil {
			return nil, e
		}
		mux.Handle("POST /v1/admin-relay", relay)
	}
	secure, err := r.material.ServerTLS()
	if err != nil {
		return nil, err
	}
	return &http.Server{Addr: net.JoinHostPort(r.spec.ServiceIP, strconv.Itoa(r.spec.PrivatePort)), Handler: mux, TLSConfig: secure, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 125 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}, nil
}

// StartHTTP binds both configured addresses before serving either listener.
func (r *clusterRuntime) StartHTTP(e *echo.Echo) (*http.Server, error) {
	private, err := r.PrivateServer(e)
	if err != nil {
		return nil, err
	}
	local, err := net.Listen("tcp", private.Addr)
	if err != nil {
		return nil, errClusterRuntime
	}
	public, err := net.Listen("tcp", r.spec.PublicListen)
	if err != nil {
		_ = local.Close()
		return nil, errClusterRuntime
	}
	r.Start() // Publication begins only after both listeners bind successfully.
	e.Server.Handler = e
	go func() {
		if err := private.Serve(tls.NewListener(local, private.TLSConfig)); err != nil && err != http.ErrServerClosed {
			slog.Error("Private node listener stopped")
			r.cancel()
		}
	}()
	go func() {
		if err := e.Server.Serve(public); err != nil && err != http.ErrServerClosed {
			slog.Error("Public authentication listener stopped")
			r.cancel()
		}
	}()
	return private, nil
}
