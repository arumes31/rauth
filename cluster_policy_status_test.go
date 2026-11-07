package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"rauth/internal/clusterstatus"
	"rauth/internal/clustertransport"
	"rauth/internal/core"
	"strings"
	"testing"
	"time"
)

func TestClusterPolicyOverviewNeverConfirmsOlderSavedSource(t *testing.T) {
	now := time.Now()
	id := noticeIdentity(4)
	publication := core.PolicyPublication{Identity: id, SourceSHA256: id.SHA256, SourceRevision: 2}
	view := clusterstatus.View{Desired: id, SourceRevision: 2, Nodes: []clusterstatus.Node{{Confirmed: true}, {Confirmed: true}}}
	assert.True(t, makePolicyOverview(view, publication, now, true, now).AllConfirmed)
	for _, tc := range []struct {
		name string
		edit func(*clusterstatus.View, *core.PolicyPublication, *time.Time, *bool)
	}{
		{"new saved edit", func(v *clusterstatus.View, _ *core.PolicyPublication, _ *time.Time, _ *bool) { v.SourceRevision++ }},
		{"new published head", func(v *clusterstatus.View, _ *core.PolicyPublication, _ *time.Time, _ *bool) {
			v.Desired = noticeIdentity(5)
		}},
		{"node pending", func(v *clusterstatus.View, _ *core.PolicyPublication, _ *time.Time, _ *bool) {
			v.Nodes[1].Confirmed = false
		}},
		{"no nodes", func(v *clusterstatus.View, _ *core.PolicyPublication, _ *time.Time, _ *bool) { v.Nodes = nil }},
		{"publication error", func(_ *clusterstatus.View, _ *core.PolicyPublication, _ *time.Time, ok *bool) { *ok = false }},
		{"capture stale", func(_ *clusterstatus.View, _ *core.PolicyPublication, checked *time.Time, _ *bool) {
			*checked = now.Add(-7 * time.Second)
		}},
		{"capture missing", func(_ *clusterstatus.View, p *core.PolicyPublication, _ *time.Time, _ *bool) { p.SourceSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := view
			v.Nodes = append([]clusterstatus.Node(nil), view.Nodes...)
			p := publication
			checked := now
			ok := true
			tc.edit(&v, &p, &checked, &ok)
			assert.False(t, makePolicyOverview(v, p, checked, ok, now).AllConfirmed)
		})
	}
}
func TestClusterPolicyStatusOnlyRegistersOnProtectedControlRoutes(t *testing.T) {
	for _, worker := range []bool{false, true} {
		called := false
		e := echo.New()
		cfg := relayConfig()
		setupRoutesWithPolicyStatus(e, cfg, worker, func(context.Context) (any, error) { called = true; return map[string]bool{"ready": true}, nil })
		registered := false
		for _, route := range e.Router().Routes() {
			if route.Path == "/rauthmgmt/policy-status" {
				registered = true
			}
		}
		assert.Equal(t, !worker, registered)
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://auth.example.com/rauthmgmt/policy-status", nil))
		assert.False(t, called)
		if !worker {
			assert.Equal(t, http.StatusFound, response.Code)
		}
	}
}
func TestClusterPolicyReceiptRequiresAuthenticatedAssignedIdentity(t *testing.T) {
	state := &clusterPolicyState{assigned: []string{}}
	response := httptest.NewRecorder()
	receiptHandler(state).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/policy-receipt", nil))
	assert.Equal(t, 403, response.Code)
	response = httptest.NewRecorder()
	relayGateFixture(t, clustertransport.PolicyRead, receiptHandler(state)).ServeHTTP(response, relayPrivateRequest(t, adminRelayEnvelope{}))
	assert.Equal(t, 403, response.Code)
}
func TestClusterPolicyReceiptRejectsSpoofedAndExcessiveJSON(t *testing.T) {
	state := &clusterPolicyState{assigned: []string{"8120081d-2a31-419b-9d35-1b74f373b07e"}}
	for _, value := range []any{map[string]string{"node_id": "other"}, map[string]string{"extra": "untrusted"}} {
		request := relayPrivateRequest(t, adminRelayEnvelope{})
		body, _ := json.Marshal(value)
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		relayGateFixture(t, clustertransport.PolicyRead, receiptHandler(state)).ServeHTTP(response, request)
		assert.Equal(t, 400, response.Code)
	}
	request := relayPrivateRequest(t, adminRelayEnvelope{})
	request.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 2049)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	relayGateFixture(t, clustertransport.PolicyRead, receiptHandler(state)).ServeHTTP(response, request)
	assert.Equal(t, 400, response.Code)
}
