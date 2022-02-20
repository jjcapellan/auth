package auth

import (
	"fmt"
	"time"

	"github.com/jjcapellan/wordgen"
	"golang.org/x/crypto/bcrypt"
)

// NewUser saves a new user in the database
//
// user: name of the user. Must be unique.
//
// password: will be used for future logins. The password is hashed before save it.
//
// email: can be an empty stryng (""). Is used for two factor validation.
//
// authLevel: this number should be used to filter user access privileges.
func NewUser(user string, password string, email string, authLevel int) error {
	salt := wordgen.New(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+salt+conf.secret), 10)
	_, err := conf.db.Exec(qryNewUser, user, string(hashedPassword), email, salt, authLevel)
	if err != nil {
		return fmt.Errorf("User %s not saved in database: %s", user, err.Error())
	}
	return nil
}

// DeleteUser deletes user register from database.
func DeleteUser(user string) error {
	_, err := conf.db.Exec(qryDeleteUser, user)
	if err != nil {
		return fmt.Errorf("User %s couldnt be deleted from database: %s", user, err.Error())
	}
	return nil
}

// UpdateUserPass updates user password
func UpdateUserPass(user string, newPassword string) error {
	salt := wordgen.New(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword+salt+conf.secret), 10)
	_, err := conf.db.Exec(qryUpdatePass, hashedPassword, salt, user)
	if err != nil {
		return fmt.Errorf("%s password couldnt be updated from database: %s", user, err.Error())
	}
	return nil
}

// UpdateUserEmail updates user email
func UpdateUserEmail(user string, newEmail string) error {
	_, err := conf.db.Exec(qryUpdateEmail, newEmail, user)
	if err != nil {
		return fmt.Errorf("%s email couldnt be updated from database: %s", user, err.Error())
	}
	return nil
}

// CheckLogin checks user password
//
// Returns (true, authLevel) if login is successful, else returns (false, 0).
func CheckLogin(user string, password string) (bool, int) {

	row := conf.db.QueryRow(qryGetUser, user)
	var hashedPassword string
	var email string
	var salt string
	var authLevel int
	err := row.Scan(&hashedPassword, &email, &salt, &authLevel)
	if err != nil {
		return false, 0
	}
	return checkPass(password, hashedPassword, salt), authLevel
}

// CheckLogin checks user password and returns result after [delay] seconds.
// This is a help against brute force attacks.
//
// Returns (true, authLevel) if login is successful, else returns (false, 0).
func CheckLoginDelayed(user string, password string, delay int) (bool, int) {
	time.Sleep(time.Duration(delay) * time.Second)
	passed, authLevel := CheckLogin(user, password)
	return passed, authLevel
}

func checkPass(password string, hashedPassword string, salt string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password+salt+conf.secret))
	if err != nil {
		return false
	}
	return true
}

func initAuthTable() error {
	_, err := conf.db.Exec(qryCreateTable)
	return err
}
