package auth

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jjcapellan/wordgen"
)

type userSession struct {
	userId    string
	exp       int64 // Expire time
	authLevel int
}

var sessionStore map[string]userSession = make(map[string]userSession)

var mtxSessionStore *sync.Mutex = &sync.Mutex{}

// NewSession creates and saves in users database and sessionStore a new session.
//
// Session expires in [duration] seconds.
//
// authLevel should be used to filter user access privileges.
func NewSession(user string, duration int, authLevel int, w http.ResponseWriter) error {
	token := createToken()
	expireTime := time.Now().Unix() + int64(duration)
	err := registerNewSession(user, token, expireTime)
	if err != nil {
		return err
	}

	objUser := userSession{user, expireTime, authLevel}

	mtxSessionStore.Lock()
	sessionStore[token] = objUser
	mtxSessionStore.Unlock()

	setSessionCookie(token, w)

	return nil
}

func GetUserAuthLevel(token string) int {
	defer mtxSessionStore.Unlock()
	mtxSessionStore.Lock()

	session, ok := sessionStore[token]
	if !ok {
		return 0
	}
	return session.authLevel
}

func createToken() string {
	randomPart := wordgen.NotSymbols(10)
	timePart := strconv.FormatInt(time.Now().UnixNano(), 10)
	return randomPart + timePart
}

func registerNewSession(user string, token string, expireTime int64) error {
	_, err := conf.db.Exec(qryNewSession, token, expireTime, user)
	if err != nil {
		log.Printf("auth token not registered in database: %s", err)
		customErr := fmt.Errorf("%s session token could not be registered in database: %s", user, err.Error())
		return customErr
	}
	return nil
}

func checkExpTime(session userSession) bool {
	return session.exp > time.Now().Unix()
}

func getUserSession(sessionId string) (userSession, error) {
	row := conf.db.QueryRow(qryGetUserSession, sessionId)
	var userId string
	var exp int64
	var authLevel int
	err := row.Scan(&userId, &exp, &authLevel)
	if err != nil {
		customErr := fmt.Errorf("Sesion Id not found in database: %s", err.Error())
		return userSession{}, customErr
	}
	return userSession{userId, exp, authLevel}, nil
}

func deleteSession(token string) error {
	mtxSessionStore.Lock()
	session := sessionStore[token]
	user := session.userId
	delete(sessionStore, token)
	mtxSessionStore.Unlock()

	_, err := conf.db.Exec(qryDeleteSession, user)
	if err != nil {
		customErr := fmt.Errorf("Sessioncold not be deleted from database: %s", err.Error())
		return customErr
	}
	return nil
}
