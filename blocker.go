package auth

import (
	"strings"
	"sync"
	"time"
)

type loginAttemps struct {
	attemps int   // Number of failed attemps
	exp     int64 // Banned expire time
}

// Stores failed logings: map[user+IP]loginAttemps
var badLoginStore map[string]loginAttemps = make(map[string]loginAttemps)

var mtxfailedLoginStore *sync.Mutex = &sync.Mutex{}

func RegBadLogin(user string, ip string) {
	key := user + strings.Split(ip, ":")[0]
	userIpRegister, ok := badLoginStore[key]
	if !ok {
		badLoginStore[key] = loginAttemps{1, time.Now().Unix() + conf.banDuration}
		return
	}

	attemps := userIpRegister.attemps
	expireTime := time.Now().Unix() + conf.banDuration
	if attemps < conf.maxAttemps {
		expireTime = 0
	}
	attemps++
	badLoginStore[key] = loginAttemps{attemps, expireTime}
}

func IsBlocked(user string, ip string) bool {
	key := user + strings.Split(ip, ":")[0]

	userIpRegister, ok := badLoginStore[key]
	if !ok {
		return false
	}

	if userIpRegister.exp < time.Now().Unix() {
		mtxfailedLoginStore.Lock()
		delete(badLoginStore, key)
		mtxfailedLoginStore.Unlock()
		return false
	}

	return true
}
