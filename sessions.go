package auth

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/jjcapellan/wordgen"
)

type UserSession struct {
	userId    string
	exp       int64 // Expire time
	authLevel int
}

var sessionStore map[string]UserSession = make(map[string]UserSession)

// NewSession creates and saves in users database and sessionStore a new session.
// Session expires in [duration] seconds.
// authLevel could be used to filter user access privileges
func NewSession(user string, duration int, authLevel int, w http.ResponseWriter) {
	token := createToken()
	expireTime := time.Now().Unix() + int64(duration)
	registerNewSession(user, token, expireTime)

	objUser := UserSession{user, expireTime, authLevel}
	sessionStore[token] = objUser

	setSessionCookie(token, w)
}

func createToken() string {
	randomPart := wordgen.NotSymbols(10)
	timePart := strconv.FormatInt(time.Now().UnixNano(), 10)
	return randomPart + timePart
}

func registerNewSession(user string, token string, expireTime int64) {
	_, err := config.db.Exec(qryNewSession, token, expireTime, user)
	if err != nil {
		log.Printf("auth token not registered in database: %s", err)
	}
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

func deleteSession(token string) {
	userSession := sessionStore[token]
	user := userSession.userId

	delete(sessionStore, token)
	_, err := config.db.Exec(qryDeleteSession, user)
	if err != nil {
		log.Printf("delete session database error: %s", err)
	}
}
