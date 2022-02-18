package auth

import (
	"strings"
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

func RegBadLogin(user string, ip string) {
	key := user + strings.Split(ip, ":")[0]
	obj, ok := badLoginStore[key]
	if !ok {
		badLoginStore[key] = userLogins{1, time.Now().Unix() + conf.banDuration}
		return
	}

	attemps := obj.attemps
	expireTime := time.Now().Unix() + conf.banDuration
	if attemps < conf.maxAttemps {
		expireTime = 0
	}
	attemps++
	badLoginStore[key] = userLogins{attemps, expireTime}
}

func IsBlocked(user string, ip string) bool {
	key := user + strings.Split(ip, ":")[0]

	obj, ok := badLoginStore[key]
	if !ok {
		return false
	}

	if obj.exp < time.Now().Unix() {
		mtxBadLoginStore.Lock()
		delete(badLoginStore, key)
		mtxBadLoginStore.Unlock()
		return false
	}

	return true
}
