package auth

import (
	"fmt"
	"net/http"
	"time"
)

// CheckAuthCookie returns error if not exists a valid session cookie in the request
func CheckAuthCookie(r *http.Request) error {
	cookie, err := r.Cookie("JJCSESID")
	if err != nil {
		return err
	}

	mtxSessionStore.Lock()
	if session, ok := sessionStore[cookie.Value]; ok {
		if !checkExpTime((session)) {
			mtxSessionStore.Unlock()
			err = fmt.Errorf("Check cookie: expired cookie")
			return err
		}
	}
	mtxSessionStore.Unlock()

	if dbSession, err := getUserSession(cookie.Value); err == nil {
		if !checkExpTime(dbSession) {
			err = fmt.Errorf("Check cookie: expired cookie")
			return err
		}
	}

	return nil
}

// LogOut deletes current session and user cookie
func LogOut(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie("JJCSESID")
	if err != nil {
		return err
	}
	err = deleteSession(cookie.Value)
	if err != nil {
		return err
	}

	newCookie := &http.Cookie{
		Name:    "JJCSESID",
		Expires: time.Now(),
		Path:    "/",
	}
	http.SetCookie(w, newCookie)

	return nil
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
