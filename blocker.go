package auth

import (
	"net"
	"sync"
	"time"
)

type userLogins struct {
	attemps int   // Number of failed attemps
	exp     int64 // Banned expire time
}

// Stores failed logings: map[user+IP]loginAttemps
var badLoginStore map[string]userLogins = make(map[string]userLogins)

var mtxBadLoginStore *sync.Mutex = &sync.Mutex{}

// RegBadLogin registers the failed login attemp.
// This function allows, together with "IsBlocked", to block during certain period of time (default 15 mins.)
// those user-ip combinations that have exceeded a certain number of attempts (default 5).
//
// remoteAddress is obtained from request -> http.Request.RemoteAddr
func RegBadLogin(user string, remoteAddress string) {
	ip, _, _ := net.SplitHostPort(remoteAddress)
	key := user + ip

	mtxBadLoginStore.Lock()
	obj, ok := badLoginStore[key]
	if !ok {
		badLoginStore[key] = userLogins{1, 0}
		mtxBadLoginStore.Unlock()
		return
	}

	attemps := obj.attemps
	expireTime := time.Now().Unix() + conf.banDuration
	if attemps < conf.maxAttemps {
		expireTime = 0
	}
	attemps++
	badLoginStore[key] = userLogins{attemps, expireTime}
	mtxBadLoginStore.Unlock()
}

// IsBlocked returns "true" if the user-ip combination is temporarily banned
// for excessive login attempts (default 5). This function must be used in conjunction
// with function "RegBadLogin".
//
// remoteAddress is obtained from request -> http.Request.RemoteAddr
func IsBlocked(user string, remoteAddress string) bool {
	ip, _, _ := net.SplitHostPort(remoteAddress)
	key := user + ip

	mtxBadLoginStore.Lock()
	obj, ok := badLoginStore[key]
	mtxBadLoginStore.Unlock()
	if !ok {
		return false
	}

	if obj.exp < time.Now().Unix() {
		if obj.attemps >= conf.maxAttemps {
			mtxBadLoginStore.Lock()
			delete(badLoginStore, key)
			mtxBadLoginStore.Unlock()
		}
		return false
	}

	return true
}
