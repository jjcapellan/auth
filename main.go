package auth

import (
	"database/sql"
)

type config struct {
	db         *sql.DB
	secret     string
	maxAttemps int
}

const maxAttemps = 5

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

	if smtpConf.From != "" {
		initSmtp(smtpConf)
	}

	err := initAuthTable()
	if err != nil {
		return err
	}
	return nil
}
