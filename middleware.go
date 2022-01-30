package auth

import (
	"log"
	"net/http"
)

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !CheckAuthCookie(r) {
			log.Println("Bad auth cookie")
			http.Redirect(w, r, config.loginUrl, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
