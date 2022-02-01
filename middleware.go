package auth

import (
	"log"
	"net/http"
)

// Middleware is a middleware function to use in the server router
//
// If auth cookie is not valid, redirects the user to login url.
//
// You could make your custom middleware using the function CheckAuthCookie
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := CheckAuthCookie(r); err != nil {
			log.Println("Bad auth cookie")
			http.Redirect(w, r, conf.loginUrl, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}
