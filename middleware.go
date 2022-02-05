package auth

import (
	"net/http"
)

// GetAuthMiddleware returns a middleware function to use in the server router.
//
// Returned middleware redirects the user to login url if auth cookie is not valid, or
// sends status unauthorized (401) if user auth level is lower than required.
func GetAuthMiddleware(authLevel int, redirectURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := CheckAuthCookie(r); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Forbidden: Not valid or expired credentials"))
				return
			}

			cookie, _ := r.Cookie("JJCSESID")
			if authValue := GetUserAuthLevel(cookie.Value); authValue < authLevel {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Insufficient authorization level"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
