# JJ-AUTH
Simple and minimal library to implement basic or two factor authentication and authorization system based on session cookies in golang.

## Usage
### **1. Installation**
Use this command to download and install in your system:
```
$ go get github.com/jjcapellan/auth
```  

And import it to your code whith:
```golang
import jjauth github.com/jjcapellan/auth
```
### **2. Initialization**
Before executing any library function, you must initialize it with this function:  

**Init(database \*sql.DB, secret string, loginURL string, smtpConfig SmtpConfig) error**
* *database*: here a table "Users" will be created if not exists.
* *secret*: random word used for cryptographic purposes. This param should be hidden in environment variable.
* *loginURL*: url of the login page (ex: "/login.html"). This url will be used by default auth middleware to redirect unathorized users.
* *smtpConfig*: can be an empty struct, in that case smtp server won't be initialized. If you want to use two factor authentication, you must provide a valid SmtpConfig struct.  

Example:
```golang
import jjauth github.com/jjcapellan/auth

var db *sql.DB
var smtpConfig jjauth.SmtpConfig = jjauth.SmtpConfig { // not necessary if 2FA is not used (=SmtpConfig{})
	From:     "user@gmail.com",
	Password: "emailpassword",
	Host:     "smtp.gmail.com",
	Port:     "587",
}

func main(){
    var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}

	// Auth module initialization
	err = jjauth.Init(db, "mysecret", "/login.html", smtpConfig)
	if err != nil {
		log.Fatal(err)
	}
    // .... more code
}

```
### **3. User registration**
New users profiles are created in "Users" table using this function:  
**NewUser(user string, password string, authLevel int, email string) error**
* *user*: name of the user. **Must be unique** (Used as primary key in database).
* *password*: be sure to force user to enter a reasonably strong password. The password is hashed before save it in the database.
* *authLevel*: this number should be used to filter user access.
* *email*: email is necessary if 2FA is used. Can be an empty string ("") but not nil.  

Example:
```golang
func signupHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")   // "John"
	pass := r.FormValue("pass")   // "a5dV2h$32Z"
	email := r.FormValue("email") // "john@email.com"

	jjauth.NewUser(user, pass, email, 1)

	// ... more code
}
```

### **4.1 Users simple login**
Simple login is managed using two functions (**CheckLogin** and **NewSession**):  

**CheckLogin(user string, password string) (bool, int)**  
* user: user name.
* password: plain text password provided by user.  
Returns (true, authLevel) if login is successful, else returns (false, 0).  
Example:
```golang
func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")

	if ok, _ := jjauth.CheckLogin(user, pass); ok {
		jjauth.NewSession(user, 60*60, 1, w) // session expires in one hour
		http.Redirect(w, r, "/membersarea/", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		log.Println("Bad login")
	}
}
```
**NewSession(user string, duration int, authLevel int, w http.ResponseWriter)**  
* *user*: user name.
* *duration*: time in seconds until the current session expires.
* *authLevel*
* *w*: used to set the session auth cookie. 

### **4.2 Two factor authentication (2FA)**
2FA adds an email verification code to the basic login. 2FA is managed using two functions:  

**New2FA(user string, password string, duration int64) error**  
This function sends a verification code to user email after user/password validation.  
* *duration*: time in seconds during which the verification code is stored. Before the time expires, the user must provide the code received by email.  

Returns an error if verification code is not sent. (Invalid user, invalid email, ...)  

**Check2FA(user string, pass2FA string) bool**  
Checks if verification code provided by user is the same sent by email and is not expired.  
Returns true if verification code is correct. In this case the verification code stored is deleted.  
Example:
```golang
func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")

	if ok := jjauth.New2FA(user, pass, 180); ok {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")   // can be hidden form field copied from login form
	vcode := r.FormValue("vcode") // verification code

	if ok := jjauth.Check2FA(user, vcode); ok {
		jjauth.NewSession(user, 60*60, 1, w)
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}
```

### *5. Users authorization*
This library provides a default authorization middleware (**Middleware**) that redirects unauthorized users to the login page.  
This middleware must be used for protected routes.  
Example:
```golang
// using gorilla/mux as router...

router := mux.NewRouter().StrictSlash(true)
fs := http.FileServer(http.Dir("./public"))

membersRouter := router.PathPrefix("/members").Subrouter()
membersRouter.Use(jjauth.Middleware)
membersRouter.Handle("/", fs)

// ...more code
```
Or you can write your custom middleware using the function **CheckAuthCookie**:  

**CheckAuthCookie(r \*http.Request) error**  
Returns error if user auth cookie is not valid (not exist, expired, ...)  
Example:
```golang
func customMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := jjauth.CheckAuthCookie(r); err != nil {
			log.Println("Bad auth cookie")
			http.Redirect(w, r, "/login.html", http.StatusSeeOther) // conf is a private object
			return
		}
		next.ServeHTTP(w, r)
	})
}
```
### **6. Users logout**
The logout is performed by the function **LogOut**:  

**LogOut(w http.ResponseWriter, r \*http.Request)**  
Deletes current session and user cookie.  
Returns error if there is not auth cookie in client or user session stored in server.  
Example:
```golang
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	jjauth.LogOut(w, r)
	http.Redirect(w, r, "/nonmembersarea/", http.StatusSeeOther)
}
```
