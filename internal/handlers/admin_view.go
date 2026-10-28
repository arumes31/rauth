package handlers

import (
	"rauth/internal/core"
	"sort"
	"strconv"
	"strings"
)

// AdminUserView is what the dashboard renders for a user. It deliberately
// omits the password hash and TOTP secret so the template can never leak them.
type AdminUserView struct {
	Username  string
	Email     string
	Groups    string
	IsAdmin   string
	Has2FA    bool
	CreatedAt int64
	Sessions  int
}

// AdminStats are the headline numbers on the dashboard overview.
type AdminStats struct {
	Users        int
	Admins       int
	With2FA      int
	Sessions     int
	OnlineUsers  int
	PublicRules  int
	FailedLogins int
}

// failedLoginActions are audit actions counted as failed sign-in attempts.
var failedLoginActions = map[string]bool{"LOGIN_FAILED": true, "2FA_FAILED": true}

// buildAdminView turns raw users, sessions and logs into sorted view models
// and overview stats. Sessions are sorted newest first, users by name.
func buildAdminView(users []core.User, sessions []map[string]string, logs []core.AuditLog, rules []BypassRuleView) ([]AdminUserView, AdminStats) {
	perUser := make(map[string]int, len(users))
	for _, s := range sessions {
		perUser[s["username"]]++
	}
	sort.SliceStable(sessions, func(i, j int) bool {
		a, _ := strconv.ParseInt(sessions[i]["created_at"], 10, 64)
		b, _ := strconv.ParseInt(sessions[j]["created_at"], 10, 64)
		return a > b
	})

	stats := AdminStats{Sessions: len(sessions), OnlineUsers: len(perUser)}
	views := make([]AdminUserView, 0, len(users))
	for _, u := range users {
		v := AdminUserView{
			Username:  u.Username,
			Email:     u.Email,
			Groups:    u.Groups,
			IsAdmin:   u.IsAdmin,
			Has2FA:    u.TwoFactor != "",
			CreatedAt: u.CreatedAt,
			Sessions:  perUser[u.Username],
		}
		if v.IsAdmin == "1" {
			stats.Admins++
		}
		if v.Has2FA {
			stats.With2FA++
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		return strings.ToLower(views[i].Username) < strings.ToLower(views[j].Username)
	})
	stats.Users = len(views)

	for _, r := range rules {
		if r.Allows() {
			stats.PublicRules++
		}
	}
	for _, l := range logs {
		if failedLoginActions[l.Action] {
			stats.FailedLogins++
		}
	}
	return views, stats
}
