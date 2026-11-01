package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"rauth/internal/clusterstatus"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"slices"
	"sync"
	"time"
)

type policySourceObservation struct {
	Revision  int64     `json:"revision"`
	SHA256    string    `json:"sha256,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Available bool      `json:"available"`
	Current   bool      `json:"current"`
}
type clusterPolicyOverview struct {
	clusterstatus.View
	Source       policySourceObservation `json:"source"`
	Confirmed    int                     `json:"confirmed"`
	AllConfirmed bool                    `json:"all_confirmed"`
}
type clusterPolicyState struct {
	store       *clusterstatus.Store
	assigned    []string
	mu          sync.Mutex
	publication core.PolicyPublication
	checkedAt   time.Time
	available   bool
}

func (s *clusterPolicyState) observed(publication core.PolicyPublication, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publication = publication
	s.checkedAt = time.Now().UTC()
	s.available = err == nil
}
func (s *clusterPolicyState) overview(ctx context.Context) (any, error) {
	view, err := s.store.View(ctx, s.assigned)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	publication, checked, available := s.publication, s.checkedAt, s.available
	s.mu.Unlock()
	return makePolicyOverview(view, publication, checked, available, time.Now()), nil
}
func makePolicyOverview(view clusterstatus.View, publication core.PolicyPublication, checked time.Time, available bool, now time.Time) clusterPolicyOverview {
	out := clusterPolicyOverview{View: view, Source: policySourceObservation{Revision: publication.SourceRevision, SHA256: publication.SourceSHA256, CheckedAt: checked, Available: available}}
	out.Source.Current = available && publication.SourceSHA256 != "" && publication.SourceRevision == view.SourceRevision && publication.Identity == view.Desired && view.Desired.Revision > 0 && now.Sub(checked) < 6*time.Second && !checked.After(now.Add(time.Second))
	for _, node := range view.Nodes {
		if node.Confirmed {
			out.Confirmed++
		}
	}
	out.AllConfirmed = out.Source.Current && len(view.Nodes) > 0 && out.Confirmed == len(view.Nodes)
	return out
}
func receiptHandler(state *clusterPolicyState) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := clustertransport.PeerForScope(r.Context(), clustertransport.PolicyRead)
		if !ok || !slices.Contains(state.assigned, peer.NodeID) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "Invalid receipt", http.StatusBadRequest)
			return
		}
		var report clusterstatus.Report
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Invalid receipt", http.StatusBadRequest)
			return
		}
		err := state.store.Record(r.Context(), peer, report)
		switch {
		case errors.Is(err, clusterstatus.ErrInvalid):
			http.Error(w, "Invalid receipt", http.StatusBadRequest)
		case errors.Is(err, clustertransport.ErrDenied):
			http.Error(w, "Forbidden", http.StatusForbidden)
		case err != nil:
			w.Header().Set("Retry-After", "5")
			http.Error(w, "Receipt storage unavailable", http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	})
}
func (r *clusterRuntime) reportPolicyStatus() {
	for r.ctx.Err() == nil {
		policy := r.worker.Status().Policy
		report := clusterstatus.Report{Applied: policy.Applied, Desired: policy.Desired, Ready: policy.Ready, LeaseExpiresAt: policy.LeaseExpiresAt}
		if r.policyState != nil {
			_ = r.policyState.store.Record(r.ctx, r.self, report)
		} else {
			r.sendPolicyReceipt(report)
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
func (r *clusterRuntime) sendPolicyReceipt(report clusterstatus.Report) {
	body, err := json.Marshal(report)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.spec.Controller.Endpoint+"/v1/policy-receipt", bytes.NewReader(body))
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.relayClient.Do(request)
	if err != nil {
		return
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
}
