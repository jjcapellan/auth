![GitHub tag (latest by date)](https://img.shields.io/github/tag-date/jjcapellan/auth.svg)
![GitHub license](https://img.shields.io/github/license/jjcapellan/auth.svg)  

# JJ-AUTH
Simple and minimal library to implement basic or two factor authentication and authorization system based on session cookies in golang.   

Generated docs: https://pkg.go.dev/github.com/jjcapellan/auth#section-documentation

## Features
* Users management
* Sessions control
* Two factor authentication (login - email)
* Authorization middleware
* User access filter by authorization levels
* Temporally bans for excessive loging attemps against one user from same ip.

## Table of contents
* [Usage](#Usage)
  * [1 Installation](#1.-Installation)
  * [2 Initialization](#2.-Initialization)
  * [3 User registration](#3.-User-registration)
  * [4.1 Users simple login](#4.1-Users-simple-login)
  * [4.2 Two factor authentication](#4.2-Two-factor-authentication-(2FA))
  * [5 Users authorization](#5.-Users-authorization)
  * [6 Users logout](#6.-Users-logout)
  * [7 Delayed login](#7.-Delayed-login)
  * [8 Ban temporally excessive login attemps](#8.-Ban-temporally-excessive-login-attemps)
* [License](#License)


## Usage
---  

### **1. Installation**
Use this command to download and install in your system:
```
$ go get github.com/jjcapellan/auth
```  

And import it to your code whith:
```golang
import jjauth github.com/jjcapellan/auth
```
---  

### **2. Initialization**
Before executing any library function, you must initialize it with this function:  

**Init(database \*sql.DB, secret string, smtpConfig SmtpConfig) error**
* *database*: here a table "Users" will be created if not exists.
* *secret*: random word used for cryptographic purposes. This param should be hidden in environment variable.
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
	err = jjauth.Init(db, "mysecret", smtpConfig)
	if err != nil {
		log.Fatal(err)
	}
    // .... more code
}

```
---  

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
---  

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
---  

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
---  

### **5. Users authorization**
This library provides a helper function **GetAuthMiddleware** to get a default middleware to be used in router.
**func GetAuthMiddleware(authLevel int, notLoggedURL string, forbiddenURL string) func(http.Handler) http.Handler**
* *authLevel*: minimum authorization level to access protected route.
* *notLoggedURL*: redirection url in case user is not logged or expired session (Ex: "/login.html"). If not defined ("") then simply returns a 403 code.
* *forbiddenURL*: redirection url in case user auth level is lower than required. If not defined ("") then simply returns a 403 code.  


Example:
```golang
// using gorilla/mux as router...

router := mux.NewRouter().StrictSlash(true)
fs := http.FileServer(http.Dir("./public"))

// "/members/..." and "/premium/..." routes only allow authenticated users

membersRouter := router.PathPrefix("/members").Subrouter()
membersRouter.Use(jjauth.GetAuthMiddleware(1, "/login.html", "")) // Auth level 1 required to enter in members area
membersRouter.Handle("/", fs)

premiumRouter := router.PathPrefix("/premium").Subrouter()
premiumRouter.Use(jjauth.GetAuthMiddleware(2, "/login.html", "")) // Auth level 2 required to enter in premium area
premiumRouter.Handle("/", fs)

router.PathPrefix("/").Handler(fs) // 

// ...more code
```
Instead use helper function **GetAuthMiddleware** you could make your custom middleware using the function **CheckAuthCookie** and **GetUserAuthLevel**:  

**CheckAuthCookie(r \*http.Request) error**  
Returns error if user auth cookie is not valid (not exist, expired, ...)  

**GetUserAuthLevel(token string) int**  
Returns 0 if session not exist. The token is stored in user cookie ("JJCSESID").  

Example:
```golang
func customMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := jjauth.CheckAuthCookie(r); err != nil {
			log.Println("Bad auth cookie")
			http.Redirect(w, r, "/login.html", http.StatusSeeOther) // conf is a private object
			return
		}
		cookie, _ := r.Cookie("JJCSESID")
		if authLevel := GetUserAuthLevel(cookie.Value); authLevel < 2 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Insufficient authorization level"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
```
---  

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

---  

### **7. Delayed login**
When two factor authentication is not used, delay the login some seconds can help against brute force attacks. There is a function for it:  
**CheckLoginDelayed(user string, password string, delay int) (bool, int)**
* *user*: user name.
* *password*: plain text password provided by user.
* *delay*: delay in seconds before return response.  
Returns (true, authLevel) if login is successful, else returns (false, 0).  

### **8. Ban temporally excessive login attemps**
There is a registry where the login attempts are stored.  
In each registry entry is stored: user, ip, number of attempts, and a time stamp (if the user-ip is baned).  
To register the login attemps this function is used:  

**RegBadLogin(user string, remoteAddress string)**  

Registers failed logins. If the combination user-ip exceeds the maximum number of attempts allowed (5 by default) then saves a time stamp indicating how long the ban will last (15 minutes by default).
* *user*: user name.
* *remoteAddress*: obtained from request using http.Request.RemoteAddr  

This function checks if a user-ip is blocked:  
**IsBlocked(user string, remoteAddress string) bool**  
* Returns true if is blocked.  

Example:  
```golang
func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	pass := r.FormValue("pass")
	
	// Before check the login, verify if user-ip is baned
	if jjauth.IsBlocked(user, r.RemoteAddr) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		log.Println("User temporally baned for excessive login attemps")
	}

	if ok, _ := jjauth.CheckLogin(user, pass); ok {
		jjauth.NewSession(user, 60*60, 1, w)
		http.Redirect(w, r, "/membersarea/", http.StatusSeeOther)
	} else {

		// Registers the failed login
		jjauth.RegBadLogin(user, r.RemoteAddr)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		log.Println("Bad login")
	}
}
```  
The default values for ban duration and max number of attemps can be changed using this functions:  
* **SetBanDuration(minutes int)**
* **SetMaxAttemps(attemps int)**


## License
This library is licensed under the terms of the [MIT open source license](LICENSE).