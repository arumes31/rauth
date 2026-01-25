package core

import (
	"fmt"
	"github.com/google/uuid"
	"time"
)

type User struct {
	Username   string `json:"username" redis:"username"`
	Password   string `json:"password" redis:"password"`
	Email      string `json:"email" redis:"email"`
	Groups     string `json:"groups" redis:"groups"`
	IsAdmin    string `json:"is_admin" redis:"is_admin"`
	TwoFactor  string `json:"2fa_secret" redis:"2fa_secret"`
	UID        string `json:"uid" redis:"uid"`
	CreatedAt  int64  `json:"created_at" redis:"created_at"`
}

func ListUsers() ([]User, error) {
	usernames, err := UserDB.SMembers(Ctx, "users").Result()
	if err != nil {
		return nil, err
	}

	var users []User
	for _, username := range usernames {
		user, err := GetUser(username)
		if err == nil {
			users = append(users, user)
		}
	}
	return users, nil
}

func GetUser(username string) (User, error) {
	var user User
	err := UserDB.HGetAll(Ctx, "user:"+username).Scan(&user)
	if err != nil {
		return user, err
	}
	if user.Username == "" {
		return user, fmt.Errorf("user not found")
	}

	// Ensure UID exists for older users
	if user.UID == "" {
		user.UID = uuid.New().String()
		UserDB.HSet(Ctx, "user:"+username, "uid", user.UID)
		UserDB.Set(Ctx, "uid:"+user.UID, username, 0)
	}

	return user, nil
}

func CreateUser(username, password, email string, isAdmin bool, twoFactor string) error {
	exists, err := UserDB.Exists(Ctx, "user:"+username).Result()
	if err != nil {
		return err
	}
	if exists > 0 {
		return fmt.Errorf("user already exists")
	}

	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	adminVal := "0"
	if isAdmin {
		adminVal = "1"
	}

	newUID := uuid.New().String()
	user := map[string]interface{}{
		"username":   username,
		"password":   hash,
		"email":      email,
		"is_admin":   adminVal,
		"groups":     "default",
		"uid":        newUID,
		"created_at": time.Now().Unix(),
		"2fa_secret": Encrypt2FASecret(twoFactor, ServerSecret),
	}

	err = UserDB.HSet(Ctx, "user:"+username, user).Err()
	if err != nil {
		return err
	}

	// Add UID index for nameless passkey login
	UserDB.Set(Ctx, "uid:"+newUID, username, 0)

	return UserDB.SAdd(Ctx, "users", username).Err()
}

func DeleteUser(username string) error {
	user, err := GetUser(username)
	if err == nil {
		UserDB.Del(Ctx, "uid:"+user.UID)
	}
	if err := UserDB.Del(Ctx, "user:"+username).Err(); err != nil {
		return err
	}
	return UserDB.SRem(Ctx, "users", username).Err()
}

func UpdateUser(username string, updates map[string]interface{}) error {
	return UserDB.HSet(Ctx, "user:"+username, updates).Err()
}

func GetUsernameByUID(uid string) (string, error) {
	return UserDB.Get(Ctx, "uid:"+uid).Result()
}