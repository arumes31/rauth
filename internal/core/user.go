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
	CreatedAt  int64  `json:"created_at" redis:"created_at"`
}

func ListUsers() ([]User, error) {
	usernames, err := UserDB.SMembers(Ctx, "users").Result()
	if err != nil {
		return nil, err
	}

	var users []User
	for _, username := range usernames {
		var user User
		err := UserDB.HGetAll(Ctx, "user:"+username).Scan(&user)
		if err == nil {
			users = append(users, user)
		}
	}
	return users, nil
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

	user := map[string]interface{}{
		"username":   username,
		"password":   hash,
		"email":      email,
		"is_admin":   adminVal,
		"groups":     "default",
		"uid":        uuid.New().String(),
		"created_at": time.Now().Unix(),
		"2fa_secret": twoFactor,
	}

	err = UserDB.HSet(Ctx, "user:"+username, user).Err()
	if err != nil {
		return err
	}
	return UserDB.SAdd(Ctx, "users", username).Err()
}

func DeleteUser(username string) error {
	if err := UserDB.Del(Ctx, "user:"+username).Err(); err != nil {
		return err
	}
	return UserDB.SRem(Ctx, "users", username).Err()
}

func UpdateUser(username string, updates map[string]interface{}) error {
	return UserDB.HSet(Ctx, "user:"+username, updates).Err()
}
