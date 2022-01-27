package auth

import (
	"database/sql"
)

type Config struct {
	db       *sql.DB
	secret   string
	loginUrl string
}

var config = &Config{}

// Init initializes all necesary objects to use this package funcions
// smtpConf can be an empty struct, in that case smtp server won't be initialized
func Init(database *sql.DB, secretKey string, loginUrl string, smtpConf SmtpConfig) error {

	config.db = database
	config.secret = secretKey
	config.loginUrl = loginUrl

	if smtpConf.From != "" {
		initSmtp(smtpConf)
	}

	err := initAuthTable()
	if err != nil {
		return err
	}
	return nil
}
