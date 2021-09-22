# JJ-AUTH
Simple and minimal library to implement basic authorization and authentication system in golang based on session cookies.  

## API functions
### Init(database *sql.DB, secret string, loginURL string) error
Initializes the system.
* database: here a table "Users" is stored.
* secret: Random word used for cryptographic purposes. This param should be hidden in environment variable.
* loginURL: url of the login page.
### NewUser(user string, password string, authLevel int) error
Saves a new user in the database.
* user: name of the user. Must be unique.
* password: will be used for future logins.
* authLevel: this number should be used to filter user access privileges.
### NewSession(user string, duration int, authLevel int, w http.ResponseWriter)
Creates a new user session.
* user: name of the user.
* duration: time in seconds before session expiration.
* authLevel: authLevel: this number should be used to filter user access privileges.
* w: is used to set the session cookie.
### CheckAuthCookie(r *http.Request) bool
Returns true if user cookie is valid.
### CheckLogin(user string, password string) (bool, int)
Returns true and authLevel if login is valid.
### LogOut(w http.ResponseWriter, r *http.Request)
Deletes user session data.
