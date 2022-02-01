package auth

import (
	"time"

	"github.com/jjcapellan/wordgen"
	"golang.org/x/crypto/bcrypt"
)

type Obj2FA struct {
	hashPass []byte
	exp      int64 // Expire time
}

var twoFactorStore map[string]Obj2FA = make(map[string]Obj2FA)

// New2FA checks user password and sends a verification code to user email
//
// The verification code is valid for [duration] seconds and is deleted after use.
func New2FA(user string, password string, duration int64) bool {
	// Check user/pass

	isUser, _ := CheckLogin(user, password)
	if !isUser {
		return false
	}

	// Get user email

	row := config.db.QueryRow(qryGetUserEmail, user)

	var email string
	err := row.Scan(&email)
	if err != nil {
		return false
	}

	// Create temp 2FA password

	pass := wordgen.NotSymbols(6)
	hashPass, _ := bcrypt.GenerateFromPassword([]byte(pass), 10)

	// Register new 2FA

	objTwoFactor := Obj2FA{}
	objTwoFactor.hashPass = hashPass
	objTwoFactor.exp = time.Now().Unix() + int64(duration)
	twoFactorStore[user] = objTwoFactor

	// Send 2FA password to user email

	msg := genMessage("Verification code", pass)
	err = sendMessage(email, msg)
	if err != nil {
		return false
	}

	return true
}

// Check2FA checks the verification code (pass2FA)
//
// Returns true if pass2FA is valid.
func Check2FA(user string, pass2FA string) bool {

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
