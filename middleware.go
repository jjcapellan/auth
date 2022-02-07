package auth

import (
	"net/http"
)

// GetAuthMiddleware returns a middleware function to use in the server router.
//
// Returned middleware redirects the user to notLoggedURL if auth cookie is not valid, or
// redirects to forbiddenURL if user auth level is lower than required. These two URLs may be
// an empty string, in which case only will be returned a 403 status code.
func GetAuthMiddleware(authLevel int, notLoggedURL string, forbiddenURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := CheckAuthCookie(r); err != nil {

				if notLoggedURL != "" {
					http.Redirect(w, r, notLoggedURL, http.StatusSeeOther)
				} else {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("Forbidden: Not valid or expired credentials"))
				}

				return
			}

			cookie, _ := r.Cookie("JJCSESID")
			if authValue := GetUserAuthLevel(cookie.Value); authValue < authLevel {

				if forbiddenURL != "" {
					http.Redirect(w, r, forbiddenURL, http.StatusSeeOther)
				} else {
					w.WriteHeader(http.StatusForbidden)
					w.Write([]byte("Forbidden: Insufficient authorization level"))
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
