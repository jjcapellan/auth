package auth

import (
	"github.com/jjcapellan/wordgen"
	"golang.org/x/crypto/bcrypt"
)

func NewUser(user string, password string, email string, authLevel int) error {
	salt := wordgen.New(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+salt+config.secret), 10)
	_, err := config.db.Exec(qryNewUser, user, string(hashedPassword), email, salt, authLevel)
	if err != nil {
		return err
	}
	return nil
}

func CheckLogin(user string, password string) (bool, int) {

	row := config.db.QueryRow(qryGetUser, user)
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

func checkPass(password string, hashedPassword string, salt string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password+salt+config.secret))
	if err != nil {
		return false
	}
	return true
}

func initAuthTable() error {
	_, err := config.db.Exec(qryCreateTable)
	return err
}
