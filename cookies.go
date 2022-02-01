package auth

import (
	"log"
	"net/http"
	"time"
)

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

// LogOut deletes current session and user cookie
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

func setSessionCookie(token string, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     "JJCSESID",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
	}

	http.SetCookie(w, cookie)
}
