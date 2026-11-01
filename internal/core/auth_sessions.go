package core

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"rauth/internal/authstate"
)

// These are selected together with artifacts/counters before HTTP starts. SQL
// mode is not exposed until every runtime security path is migrated.
var securitySessions authstate.SessionStore
var securitySessionAbsoluteTTL time.Duration

func ReadAuthSession(ctx context.Context, token string) (map[string]string, error) {
	if securitySessions != nil {
		value, err := securitySessions.Get(ctx, token)
		if err != nil {
			return nil, err
		}
		fields := make(map[string]string, len(value.Fields)+7)
		for k, v := range value.Fields {
			fields[k] = v
		}
		delete(fields, "rotated_to")
		delete(fields, "token")
		fields["status"] = "valid"
		fields["session_family"] = value.FamilyID
		fields["username"] = value.Username
		fields["auth_gen"] = strconv.FormatInt(value.Generation, 10)
		fields["ip"] = value.IP
		fields["created_at"] = strconv.FormatInt(value.IssuedAt.Unix(), 10)
		if value.Successor != "" {
			fields["rotated_to"] = value.Successor
		}
		return fields, nil
	}
	if TokenDB == nil {
		return nil, errors.New("session authority unavailable")
	}
	return TokenDB.HGetAll(ctx, "X-rauth-authtoken="+token).Result()
}
func RevokeAuthSession(ctx context.Context, token string) error {
	if securitySessions != nil {
		return securitySessions.Revoke(ctx, token)
	}
	if TokenDB == nil {
		return errors.New("session authority unavailable")
	}
	key := "X-rauth-authtoken=" + token
	fields, err := TokenDB.HMGet(ctx, key, "username", "ip").Result()
	if err != nil {
		return err
	}
	user, _ := fields[0].(string)
	ip, _ := fields[1].(string)
	pipe := TokenDB.TxPipeline()
	pipe.Del(ctx, key, "bypass_unlock:"+token)
	if user != "" {
		pipe.SRem(ctx, "user_sessions:"+user, token)
	}
	if ip != "" {
		pipe.SRem(ctx, "ip_sessions:"+ip, token)
	}
	_, err = pipe.Exec(ctx)
	return err
}
func storeSQLSession(token, username, ip string, fields map[string]interface{}, validity time.Duration) error {
	data := make(map[string]string, len(fields))
	for key, value := range fields {
		if flag, ok := value.(bool); ok {
			if flag {
				data[key] = "1"
			} else {
				data[key] = "0"
			}
		} else {
			data[key] = fmt.Sprint(value)
		}
	}
	if status := data["status"]; status != "" && status != "valid" {
		return errors.New("only authenticated sessions can be issued")
	}
	gen, err := strconv.ParseInt(SessionGen(data), 10, 64)
	if err != nil || gen < 0 {
		return authstate.ErrStaleGeneration
	}
	return securitySessions.Issue(Ctx, token, authstate.IssueSession{Username: username, Generation: gen, IP: ip, Fields: data, IdleTTL: validity, AbsoluteTTL: securitySessionAbsoluteTTL})
}

var replaceWithGrantScript = redis.NewScript(`
if redis.call("EXISTS",KEYS[1])==0 or redis.call("HEXISTS",KEYS[1],"rotated_to")==1 then return 0 end
if redis.call("HGET",KEYS[1],"username")~=ARGV[3] or (redis.call("HGET",KEYS[1],"auth_gen") or "0")~=ARGV[4] then return 0 end
if redis.call("EXISTS",KEYS[2])==1 then return -1 end
local ttl=redis.call("PTTL",KEYS[1]);if ttl==0 or ttl==-2 then return 0 end;local grant=tonumber(ARGV[5]);if ttl>0 and ttl<grant then grant=ttl end
redis.call("HSETNX",KEYS[1],"session_family",ARGV[6])
redis.call("HSET",KEYS[2],unpack(redis.call("HGETALL",KEYS[1])))
if ttl>0 then redis.call("PEXPIRE",KEYS[2],ttl) end
redis.call("DEL",KEYS[1],KEYS[5]);redis.call("SREM",KEYS[3],ARGV[1]);redis.call("SADD",KEYS[3],ARGV[2]);redis.call("SREM",KEYS[4],ARGV[1]);redis.call("SADD",KEYS[4],ARGV[2])
redis.call("PSETEX",KEYS[6],grant,ARGV[3]);return 1`)

func ReplaceSessionWithPublicAccessGrant(ctx context.Context, oldToken, newToken, user, generation string, ttl time.Duration) (bool, error) {
	if generation == "" {
		generation = "0"
	}
	gen, err := strconv.ParseInt(generation, 10, 64)
	if err != nil || gen < 0 {
		return false, authstate.ErrStaleGeneration
	}
	if user == "" || oldToken == "" || newToken == "" || oldToken == newToken || ttl < time.Second || ttl > 15*time.Minute {
		return false, errors.New("invalid step-up grant")
	}
	if securitySessions != nil {
		return securitySessions.ReplaceWithGrant(ctx, oldToken, newToken, authstate.PublicAccessGrant{Username: user, Generation: gen, TTL: ttl})
	}
	if TokenDB == nil {
		return false, errors.New("session authority unavailable")
	}
	ip, err := TokenDB.HGet(ctx, "X-rauth-authtoken="+oldToken, "ip").Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return false, err
	}
	n, err := replaceWithGrantScript.Run(ctx, TokenDB, []string{"X-rauth-authtoken=" + oldToken, "X-rauth-authtoken=" + newToken, "user_sessions:" + user, "ip_sessions:" + ip, "bypass_unlock:" + oldToken, "bypass_unlock:" + newToken}, oldToken, newToken, user, generation, ttl.Milliseconds(), legacyManagedHandle(oldToken)).Int()
	if err == nil && n < 0 {
		return false, authstate.ErrConflict
	}
	return n == 1, err
}

var grantRemainingScript = redis.NewScript(`if redis.call("GET",KEYS[1])~=ARGV[1] then return 0 end return redis.call("PTTL",KEYS[1])`)

func PublicAccessGrantRemaining(ctx context.Context, token, user string) (time.Duration, error) {
	if securitySessions != nil {
		return securitySessions.GrantRemaining(ctx, token, user)
	}
	if TokenDB == nil {
		return 0, errors.New("session authority unavailable")
	}
	millis, err := grantRemainingScript.Run(ctx, TokenDB, []string{"bypass_unlock:" + token}, user).Int64()
	if millis < 0 {
		millis = 0
	}
	return time.Duration(millis) * time.Millisecond, err
}
func LockPublicAccessGrant(ctx context.Context, token string) error {
	if securitySessions != nil {
		return securitySessions.LockGrant(ctx, token)
	}
	if TokenDB == nil {
		return errors.New("session authority unavailable")
	}
	return TokenDB.Del(ctx, "bypass_unlock:"+token).Err()
}

// RegistrationSessionBinding follows the stable browser family, never a
// rotation token. The HttpOnly one-use ceremony cookie and generation remain
// separate requirements. An authority read error never uses another backend.
func RegistrationSessionBinding(ctx context.Context, token, secret string) (string, error) {
	data, err := ReadAuthSession(ctx, token)
	if err != nil {
		return "", err
	}
	if data["status"] != "valid" || data["username"] == "" {
		return "", authstate.ErrNotFound
	}
	identity := data["session_family"]
	if identity == "" {
		if securitySessions != nil {
			return "", errors.New("session family is missing")
		}
		// Older legacy sessions gain this exact value during their next atomic
		// rotation/replacement, so starting a ceremony before rotation also works.
		identity = legacyManagedHandle(token)
	}
	return RegistrationBrowserBinding(identity, secret), nil
}
