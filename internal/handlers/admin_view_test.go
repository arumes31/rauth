package handlers

import (
	"rauth/internal/core"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAdminView(t *testing.T) {
	users := []core.User{
		{Username: "zoe", IsAdmin: "0", Password: "hash", TwoFactor: "SECRET"},
		{Username: "Adam", IsAdmin: "1", Password: "hash"},
		{Username: "bob", IsAdmin: "0", Email: "bob@example.com", TwoFactor: "SECRET2"},
	}
	sessions := []map[string]string{
		{"username": "bob", "created_at": "100"},
		{"username": "zoe", "created_at": "300"},
		{"username": "bob", "created_at": "200"},
	}
	logs := []core.AuditLog{{Action: "LOGIN_FAILED"}, {Action: "2FA_FAILED"}, {Action: "LOGIN_SUCCESS"}}
	rules := []BypassRuleView{
		{BypassRule: core.BypassRule{Rule: "a.example.com", Action: core.BypassAllow}},
		{BypassRule: core.BypassRule{Rule: "a.example.com/x", Action: core.BypassDeny}},
	}

	views, stats := buildAdminView(users, sessions, logs, rules)

	require.Len(t, views, 3)
	assert.Equal(t, []string{"Adam", "bob", "zoe"}, []string{views[0].Username, views[1].Username, views[2].Username}, "sorted case-insensitively")
	assert.False(t, views[0].Has2FA)
	assert.True(t, views[1].Has2FA)
	assert.Equal(t, 2, views[1].Sessions)
	assert.Equal(t, 1, views[2].Sessions)
	assert.Equal(t, 0, views[0].Sessions)

	assert.Equal(t, "300", sessions[0]["created_at"], "sessions sorted newest first")
	assert.Equal(t, "100", sessions[2]["created_at"])

	assert.Equal(t, AdminStats{Users: 3, Admins: 1, With2FA: 2, Sessions: 3, OnlineUsers: 2, PublicRules: 1, FailedLogins: 2}, stats)
}
