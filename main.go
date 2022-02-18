package auth

import (
	"database/sql"
)

type config struct {
	db          *sql.DB
	secret      string
	maxAttemps  int   // login attems before ban specific combination user/IP
	banDuration int64 // ban duration in seconds
}

const maxAttemps = 5
const banDuration = int64(60 * 15) // 15 minutes

var conf = &config{}

// Init initializes all necesary objects to use this package funcions
//
// database: here a table "Users" is stored
//
// secretKey: Random word used for cryptographic purposes
//
// smtpConf: can be an empty struct, in that case smtp server won't be initialized
func Init(database *sql.DB, secretKey string, smtpConf SmtpConfig) error {

	conf.db = database
	conf.secret = secretKey
	conf.maxAttemps = maxAttemps
	conf.banDuration = banDuration

	if smtpConf.From != "" {
		initSmtp(smtpConf)
	}

	err := initAuthTable()
	if err != nil {
		return err
	}
	return nil
}

func SetBanDuration(minutes int) {
	conf.banDuration = int64(minutes * 60)
}

func SetMaxAttemps(attemps int) {
	if attemps < 1 {
		return
	}
	conf.maxAttemps = attemps
}
