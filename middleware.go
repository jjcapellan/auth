package auth

import (
	"log"
	"net/http"
)

// GetAuthMiddleware returns a middleware function to use in the server router.
//
// Returned middleware redirects the user to login url if auth cookie is not valid, or
// sends status unauthorized (401) if user auth level is lower than required.
func GetAuthMiddleware(authLevel int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := CheckAuthCookie(r); err != nil {
				log.Println("Bad auth cookie")
				http.Redirect(w, r, conf.loginUrl, http.StatusSeeOther)
				return
			}

			cookie, _ := r.Cookie("JJCSESID")
			if authValue := GetUserAuthLevel(cookie.Value); authValue < authLevel {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Insufficient authorization level"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
