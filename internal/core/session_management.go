package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"rauth/internal/authstate"
)

var ErrInvalidSessionHandle = errors.New("invalid session handle")

type ManagedSessionPage struct {
	Sessions []map[string]string
	Next     string
}

// ListManagedSessions returns display metadata and non-bearer revocation handles.
// SQL uses bounded keyset pagination. The legacy adapter retains its single-node
// listing behavior only until the coordinated authority cutover.
func ListManagedSessions(ctx context.Context, user, currentToken, after string, limit int) (ManagedSessionPage, error) {
	var result ManagedSessionPage
	if limit < 1 || limit > 200 {
		return result, ErrInvalidSessionHandle
	}
	if securitySessions != nil {
		currentFamily := ""
		if currentToken != "" {
			current, err := securitySessions.Get(ctx, currentToken)
			if err != nil && !errors.Is(err, authstate.ErrNotFound) {
				return result, err
			}
			if err == nil {
				currentFamily = current.FamilyID
			}
		}
		page, err := securitySessions.List(ctx, user, after, limit)
		if errors.Is(err, authstate.ErrInvalidSessionCursor) {
			return result, ErrInvalidSessionHandle
		}
		if err != nil {
			return result, err
		}
		result.Next = page.Next
		for _, session := range page.Sessions {
			fields := sessionDisplayFields(session.Fields)
			fields["handle"], fields["username"], fields["ip"] = session.Handle, session.Username, session.IP
			fields["created_at"] = strconv.FormatInt(session.IssuedAt.Unix(), 10)
			expires := session.IdleExpiresAt
			if session.AbsoluteExpiresAt.Before(expires) {
				expires = session.AbsoluteExpiresAt
			}
			fields["ttl"] = strconv.FormatInt(int64(max(0, expires.Sub(page.ObservedAt).Seconds())), 10)
			fields["is_current"] = "0"
			if currentFamily == session.Handle {
				fields["is_current"] = "1"
			}
			result.Sessions = append(result.Sessions, fields)
		}
		return result, nil
	}
	if after != "" {
		return result, ErrInvalidSessionHandle
	}
	if TokenDB == nil {
		return result, errors.New("session authority unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tokens, err := legacyManagedTokens(ctx, user)
	if err != nil {
		return result, err
	}
	pipe := TokenDB.Pipeline()
	details := make([]*redis.MapStringStringCmd, len(tokens))
	ttls := make([]*redis.DurationCmd, len(tokens))
	for i, token := range tokens {
		details[i] = pipe.HGetAll(ctx, "X-rauth-authtoken="+token)
		ttls[i] = pipe.TTL(ctx, "X-rauth-authtoken="+token)
	}
	if len(tokens) > 0 {
		if _, err = pipe.Exec(ctx); err != nil {
			return result, err
		}
	}
	for i, token := range tokens {
		data, err := details[i].Result()
		if err != nil {
			return result, err
		}
		if len(data) == 0 || data["username"] == "" || (user != "" && data["username"] != user) || data["rotated_to"] != "" {
			continue
		}
		if status := data["status"]; status != "" && status != "valid" {
			continue
		}
		fields := sessionDisplayFields(data)
		fields["handle"], fields["username"], fields["ip"], fields["created_at"] = legacyManagedHandle(token), data["username"], data["ip"], data["created_at"]
		fields["ttl"] = strconv.FormatInt(int64(ttls[i].Val().Seconds()), 10)
		fields["is_current"] = "0"
		if token == currentToken {
			fields["is_current"] = "1"
		}
		result.Sessions = append(result.Sessions, fields)
	}
	return result, nil
}

func sessionDisplayFields(data map[string]string) map[string]string {
	fields := make(map[string]string)
	for _, key := range []string{"country", "user_agent", "ua_ch_platform", "ua_ch_mobile", "ua_ch_model", "groups", "is_admin"} {
		if value, ok := data[key]; ok {
			fields[key] = value
		}
	}
	return fields
}
func legacyManagedHandle(token string) string {
	mac := hmac.New(sha256.New, hkdfKey(ServerSecret, "rauth-session-management-v1"))
	mac.Write([]byte(token))
	return "legacy:" + hex.EncodeToString(mac.Sum(nil))
}
func legacyManagedTokens(ctx context.Context, user string) ([]string, error) {
	if user != "" {
		return TokenDB.SMembers(ctx, "user_sessions:"+user).Result()
	}
	var result []string
	var cursor uint64
	for {
		keys, next, err := TokenDB.Scan(ctx, cursor, "X-rauth-authtoken=*", 200).Result()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			result = append(result, strings.TrimPrefix(key, "X-rauth-authtoken="))
		}
		// Bound legacy discovery too; SQL pagination handles larger installations.
		if len(result) > 10000 {
			return nil, errors.New("legacy session listing exceeds limit")
		}
		cursor = next
		if cursor == 0 {
			return result, nil
		}
	}
}

var revokeManagedSessionScript = redis.NewScript(`
local owner=redis.call("HGET",KEYS[1],"username")
if not owner or (ARGV[1]~="" and owner~=ARGV[1]) then return 0 end
local ip=redis.call("HGET",KEYS[1],"ip")
redis.call("DEL",KEYS[1],KEYS[2]);redis.call("SREM","user_sessions:"..owner,ARGV[2])
if ip then redis.call("SREM","ip_sessions:"..ip,ARGV[2]) end
return 1`)

// Empty owner is reserved for an already-authorized administrator. Profile
// handlers always pass their authenticated account, never a submitted owner.
func RevokeManagedSession(ctx context.Context, handle, owner string) (bool, error) {
	if handle == "" {
		return false, ErrInvalidSessionHandle
	}
	if securitySessions != nil {
		if _, err := uuid.Parse(handle); err != nil {
			return false, ErrInvalidSessionHandle
		}
		return securitySessions.RevokeFamily(ctx, handle, owner)
	}
	if TokenDB == nil {
		return false, errors.New("session authority unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	token := handle
	if strings.HasPrefix(handle, "legacy:") {
		if len(handle) != len("legacy:")+64 {
			return false, ErrInvalidSessionHandle
		}
		tokens, err := legacyManagedTokens(ctx, owner)
		if err != nil {
			return false, err
		}
		token = ""
		for _, candidate := range tokens {
			if hmac.Equal([]byte(legacyManagedHandle(candidate)), []byte(handle)) {
				token = candidate
				break
			}
		}
		if token == "" {
			return false, nil
		}
	}
	// Old forms remain accepted by the legacy authority during rolling upgrades.
	// SQL never interprets a submitted bearer token as a management identifier.
	n, err := revokeManagedSessionScript.Run(ctx, TokenDB, []string{"X-rauth-authtoken=" + token, "bypass_unlock:" + token}, owner, token).Int()
	return n == 1, err
}
