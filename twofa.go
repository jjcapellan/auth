package auth

import (
	"fmt"
	"sync"
	"time"

	"github.com/jjcapellan/wordgen"
	"golang.org/x/crypto/bcrypt"
)

type obj2FA struct {
	hashPass []byte
	exp      int64 // Expire time
}

var twoFactorStore map[string]obj2FA = make(map[string]obj2FA)

var mtx2FStore *sync.Mutex = &sync.Mutex{}

// New2FA checks user password and sends a verification code to user email
//
// The verification code is valid for [duration] seconds and is deleted after use
//
// Returns an error if verification code is not sent
func New2FA(user string, password string, duration int64) error {
	// Check user/pass

	isUser, _ := CheckLogin(user, password)
	if !isUser {
		return fmt.Errorf("Verification code not sent to user %s: invalid user", user)
	}

	// Get user email

	row := conf.db.QueryRow(qryGetUserEmail, user)

	var email string
	err := row.Scan(&email)
	if err != nil {
		return fmt.Errorf("Verification code not sent: %s", err.Error())
	}

	// Create temp 2FA password

	pass := wordgen.NotSymbols(6)
	hashPass, _ := bcrypt.GenerateFromPassword([]byte(pass), 10)

	// Register new 2FA

	obj2f := obj2FA{}
	obj2f.hashPass = hashPass
	obj2f.exp = time.Now().Unix() + int64(duration)

	mtx2FStore.Lock()
	twoFactorStore[user] = obj2f
	mtx2FStore.Unlock()

	// Send 2FA password to user email

	msg := genMessage("Verification code", pass)
	err = sendMessage(email, msg)
	if err != nil {
		return fmt.Errorf("Verification code not sent: %s", err.Error())
	}

	return nil
}

// Check2FA checks the verification code (pass2FA)
//
// Returns true if pass2FA is valid.
func Check2FA(user string, pass2FA string) bool {

	defer mtx2FStore.Unlock()
	mtx2FStore.Lock()

	exp := twoFactorStore[user].exp
	if exp < time.Now().Unix() {
		return false
	}

	err := bcrypt.CompareHashAndPassword(twoFactorStore[user].hashPass, []byte(pass2FA))
	if err != nil {
		return false
	}

	delete(twoFactorStore, user)

	return true
}
