package authstate

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("authentication state not found or expired")
var ErrStaleGeneration = errors.New("authentication proof was revoked")
var ErrConflict = errors.New("session token already exists")
var ErrBusy = errors.New("authentication state is busy; retry")

// SessionStore is deliberately separate from challenge/grant/counter stores.
// Rotate/Replace return ErrBusy for transient family-lock contention; callers
// can retain/retry the current token rather than treating it as expired.
// Every operation uses SQL authority; there is no positive authorization cache.
// Revoke invalidates the entire family, including concurrent rotations and
// future app sessions linked by SSO. Refresh cannot extend absolute expiry.
type SessionStore interface {
	Issue(context.Context, string, IssueSession) error
	Get(context.Context, string) (Session, error)
	Rotate(context.Context, string, string, time.Duration, time.Duration) (bool, error)
	Replace(context.Context, string, string) (bool, error)
	Refresh(context.Context, string, time.Duration) (bool, error)
	Revoke(context.Context, string) error
	RevokeUser(context.Context, string) error
	RevokeUserFamilies(context.Context, string) error
	Restamp(context.Context, string, int64, int64) (bool, error)
	ReplaceWithGrant(context.Context, string, string, PublicAccessGrant) (bool, error)
	GrantRemaining(context.Context, string, string) (time.Duration, error)
	LockGrant(context.Context, string) error
	List(context.Context, string, string, int) (SessionPage, error)
	RevokeFamily(context.Context, string, string) (bool, error)
	RevokeOthers(context.Context, string, string) error
	HasActiveForIP(context.Context, string) (bool, error)
	ActiveCount(context.Context) (int64, error)
	UpdateCountry(context.Context, string, string) (bool, error)
}

type IssueSession struct {
	Username    string
	Generation  int64
	IP          string
	Fields      map[string]string
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
}
type Session struct {
	Username          string
	Generation        int64
	IP                string
	FamilyID          string
	Audience          string // Empty for the canonical login; exact HTTPS origin for an app.
	Fields            map[string]string
	Successor         string
	IssuedAt          time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}
type sessionPayload struct {
	IP        string            `json:"ip"`
	Fields    map[string]string `json:"fields"`
	Successor string            `json:"successor,omitempty"`
}
