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

func RegBadLogin(user string, ip string) {
	_ip, _, _ := net.SplitHostPort(ip)
	key := user + _ip

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

func IsBlocked(user string, ip string) bool {
	_ip, _, _ := net.SplitHostPort(ip)
	key := user + _ip

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
