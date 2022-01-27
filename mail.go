package auth

import (
	"net/smtp"
)

type SmtpConfig struct {
	From     string
	Password string
	Host     string
	Port     string
}

type MailConfig struct {
	SmtpConfig
	auth smtp.Auth
}

var mailConfig = &MailConfig{}

func initSmtp(smtpConf SmtpConfig) {
	mailConfig.SmtpConfig = smtpConf
	mailConfig.auth = smtp.PlainAuth("", smtpConf.From, smtpConf.Password, smtpConf.Host)
}

func genMessage(subject string, body string) (msg string) {
	return "Subject: " + subject + "\r\n\r\n" + body + "\r\n"
}

func sendMessage(to string, message string) error {
	msg := "From: " + mailConfig.From + "\r\n" + "To: " + to + "\r\n" + message
	err := smtp.SendMail(mailConfig.Host+":"+mailConfig.Port, mailConfig.auth, mailConfig.From, []string{to}, []byte(msg))
	return err
}
