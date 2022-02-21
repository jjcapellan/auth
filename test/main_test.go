package authtest

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jjauth "github.com/jjcapellan/auth"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func TestMain(t *testing.T) {

	// Init database
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Error opening database")
	}
	// Server
	go startServer()

	// Init jjauth
	err = jjauth.Init(db, "mysecret", jjauth.SmtpConfig{})
	if err != nil {
		t.Fatalf("Init error: %s", err.Error())
	}

	// Add user
	err = jjauth.NewUser("user1", "pass1", "email1@email.com", 1)
	if err != nil {
		t.Fatalf("NewUser error: %s", err)
	}

	// Test user1 cycle

	// 1. - Test CheckLogin
	testCheckLogin("user1", "pass1", true, 1, t)
	testCheckLogin("user1", "ahsgfdsg", false, 1, t)
	testCheckLogin("Unknowuser", "ahsgfdsg", false, 0, t)

	// 2. Test NewSession
	sessionCookie := testNewSession("user1", 2, 1, t) // create session which expires in 2 seconds

	// 3. Test Authorization Middleware
	testMiddleware(sessionCookie, t)

	// 4. Test LogOut
	testLogOut(t)

	// 5. Test user-ip ban system
	testBanSystem(t)

}

func testCheckLogin(user string, password string, expecdOk bool, expecAuthLevel int, t *testing.T) {
	ok, authLevel := jjauth.CheckLogin(user, password)
	if ok != expecdOk {
		t.Fatalf("CheckLogin ok expected: %t  Got: %t", expecdOk, ok)
	}
	if authLevel != expecAuthLevel {
		t.Fatalf("CheckLogin authlevel expected: %d  Got: %d", expecAuthLevel, authLevel)
	}
}

func testNewSession(user string, seconds int, authLevel int, t *testing.T) *http.Cookie {
	w := httptest.NewRecorder()
	err := jjauth.NewSession(user, seconds, authLevel, w)
	if err != nil {
		t.Fatalf("NewSession error: %s", err.Error())
	}
	sessionCookie := w.Result().Cookies()[0]
	return sessionCookie
}

func testMiddleware(sessionCookie *http.Cookie, t *testing.T) {
	checkRoute("http://localhost:3000/members", "members", "Loged user to /members ->", sessionCookie, t)
	checkRoute("http://localhost:3000/vip", "forbidden", "Insufficient authLevel to /vip ->", sessionCookie, t)
	checkRoute("http://localhost:3000/public", "public", "Loged to /public ->", sessionCookie, t)
	time.Sleep(3 * time.Second)
	checkRoute("http://localhost:3000/members", "notloged", "Expired session to members ->", sessionCookie, t)
	checkRoute("http://localhost:3000/members", "notloged", "Not member to members ->", &http.Cookie{}, t)
}

func testLogOut(t *testing.T) {
	sessionCookie := testNewSession("user1", 60, 1, t)
	cookieValue := sessionCookie.Value

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://localhost:3000/logout", nil)
	r.Header.Add("Cookie", sessionCookie.String())

	jjauth.LogOut(w, r)
	cookieDeletedValue := w.Result().Cookies()[0].Value
	if cookieValue == cookieDeletedValue && cookieDeletedValue != "" {
		t.Fatalf("LogOut -> Session cookie value not deleted: %s", cookieDeletedValue)
	}
}

func testBanSystem(t *testing.T) {
	// Max login attemps allowed = 3
	jjauth.SetMaxAttemps(3)
	jjauth.RegBadLogin("user2", "120.120.120.130:4565") // 1º attemp
	isBlocked := jjauth.IsBlocked("user2", "120.120.120.130:4565")
	if isBlocked {
		t.Fatalf("Ban system -> User baned with only one login attemp of three")
	}
	jjauth.RegBadLogin("user2", "120.120.120.130:4565") // 2º attemp
	isBlocked = jjauth.IsBlocked("user2", "120.120.120.130:4565")
	if isBlocked {
		t.Fatalf("Ban system -> User baned with only two login attemps of three")
	}
	jjauth.RegBadLogin("user2", "120.120.120.130:4565") // 3º attemp
	isBlocked = jjauth.IsBlocked("user2", "120.120.120.130:4565")
	if isBlocked {
		t.Fatalf("Ban system -> User baned with only three login attemps of three")
	}
	jjauth.RegBadLogin("user2", "120.140.12.1:4565")
	isBlocked = jjauth.IsBlocked("user2", "120.120.120.130:4565")
	if isBlocked {
		t.Fatalf("Ban system -> User baned with first login attemp from different IP")
	}
	jjauth.RegBadLogin("user2", "120.120.120.130:4565") // 4º attemp
	isBlocked = jjauth.IsBlocked("user2", "120.120.120.130:4565")
	if !isBlocked {
		t.Fatalf("Ban system -> User allowed with four login attemps of three")
	}

}

// Helpers

func checkRoute(reqURL string, expectedRes string, testName string, cookie *http.Cookie, t *testing.T) {
	// Client
	client := &http.Client{}
	// Request
	request, _ := http.NewRequest("GET", reqURL, nil)
	request.AddCookie(cookie)
	// Response
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("Request error")
	}
	body, _ := io.ReadAll(response.Body)
	defer response.Body.Close()

	if string(body) != expectedRes {
		t.Fatalf("%s Expected response: %s  Got: %s", testName, expectedRes, string(body))
	}
}
