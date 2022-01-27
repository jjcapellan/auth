package auth

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/jjcapellan/wordgen"
	"golang.org/x/crypto/bcrypt"
)

type UserSession struct {
	userId    string
	exp       int64 // Expire time
	authLevel int
}

type Obj2FA struct {
	hashPass []byte
	exp      int64 // Expire time
}

type Config struct {
	db       *sql.DB
	secret   string
	loginUrl string
}

var config = &Config{}

var sessionStore map[string]UserSession
var twoFactorStore map[string]Obj2FA

//////////////////////////////

func Init(database *sql.DB, secretKey string, loginUrl string, smtpConf SmtpConfig) error {
	sessionStore = make(map[string]UserSession)
	twoFactorStore = make(map[string]Obj2FA)

	config.db = database
	config.secret = secretKey
	config.loginUrl = loginUrl

	if smtpConf.from != "" {
		initSmtp(smtpConf)
	}

	err := createAuthTable()
	if err != nil {
		return err
	}
	return nil
}

func createAuthTable() error {
	_, err := config.db.Exec(qryCreateTable)
	return err
}

////////////////////////

func NewUser(user string, password string, email string, authLevel int) error {
	salt := wordgen.New(8)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password+salt+config.secret), 10)
	_, err := config.db.Exec(qryNewUser, user, string(hashedPassword), email, salt, authLevel)
	if err != nil {
		return err
	}
	return nil
}

////////////////////////

func NewSession(user string, duration int, authLevel int, w http.ResponseWriter) {
	token := createToken()
	expireTime := getExpireTime(duration)
	registerNewSession(user, token, expireTime)

	objUser := UserSession{user, expireTime, authLevel}
	sessionStore[token] = objUser

	setSessionCookie(token, w)
}

////////////////////////

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
	objTwoFactor.exp = getExpireTime(180)
	twoFactorStore[user] = objTwoFactor

	// Send 2FA password to user email
	msg := genMessage("Verification code", pass)
	err = sendMessage(email, msg)
	if err != nil {
		return false
	}

	return true
}

func createToken() string {
	randomPart := wordgen.NotSymbols(10)
	timePart := strconv.FormatInt(time.Now().UnixNano(), 10)
	return randomPart + timePart
}

func getExpireTime(duration int) int64 {
	return time.Now().Unix() + int64(duration)
}

func registerNewSession(user string, token string, expireTime int64) {
	_, err := config.db.Exec(qryNewSession, token, expireTime, user)
	if err != nil {
		log.Printf("auth token not registered in database: %s", err)
	}
}

func setSessionCookie(token string, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "JJCSESID",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	}

	http.SetCookie(w, cookie)
}

////////////////////////////////////////

// CheckAuthCookie returns true if exists a valid session cookie in the request
func CheckAuthCookie(r *http.Request) bool {
	cookie, err := r.Cookie("JJCSESID")
	if err != nil {
		return false
	}

	if userSession, ok := sessionStore[cookie.Value]; ok {
		return checkExpTime(userSession)
	}

	if dbUserSession, err := getUserSession(cookie.Value); err == nil {
		return checkExpTime(dbUserSession)
	}

	return false
}

func checkExpTime(userSession UserSession) bool {
	return userSession.exp > time.Now().Unix()
}

func getUserSession(sessionId string) (UserSession, error) {
	row := config.db.QueryRow(qryGetUserSession, sessionId)
	var userId string
	var exp int64
	var authLevel int
	err := row.Scan(&userId, &exp, &authLevel)
	if err != nil {
		return UserSession{}, err
	}
	return UserSession{userId, exp, authLevel}, nil
}

//////////////////////////////

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

//////////////////////////////////

func LogOut(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("JJCSESID")
	if err != nil {
		log.Printf("LogOut cookie error: %s", err)
	}
	deleteSession(cookie.Value)

	newCookie := &http.Cookie{
		Name:    "JJCSESID",
		Expires: time.Now(),
		Path:    "/",
	}
	http.SetCookie(w, newCookie)
}

func deleteSession(token string) {
	userSession := sessionStore[token]
	user := userSession.userId

	delete(sessionStore, token)
	_, err := config.db.Exec(qryDeleteSession, user)
	if err != nil {
		log.Printf("delete session database error: %s", err)
	}
}
