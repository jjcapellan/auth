package auth

import (
	"net/smtp"
)

type SmtpConfig struct {
	from     string
	password string
	host     string
	port     string
}

type MailConfig struct {
	SmtpConfig
	auth smtp.Auth
}

var mailConfig = &MailConfig{}

func initSmtp(smtpConf SmtpConfig) {
	mailConfig.SmtpConfig = smtpConf
	mailConfig.auth = smtp.PlainAuth("", smtpConf.from, smtpConf.password, smtpConf.host)
}

func genMessage(subject string, body string) (msg string) {
	return "Subject: " + subject + "\r\n\r\n" + body + "\r\n"
}

func sendMessage(to string, message string) error {
	msg := "From: " + mailConfig.from + "\r\n" + "To: " + to + "\r\n" + message
	err := smtp.SendMail(mailConfig.host+":"+mailConfig.port, mailConfig.auth, mailConfig.from, []string{to}, []byte(msg))
	return err
}
