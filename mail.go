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

type mailConfig struct {
	SmtpConfig
	auth smtp.Auth
}

var mailConf = &mailConfig{}

func initSmtp(smtpConf SmtpConfig) {
	mailConf.SmtpConfig = smtpConf
	mailConf.auth = smtp.PlainAuth("", smtpConf.From, smtpConf.Password, smtpConf.Host)
}

func genMessage(subject string, body string) (msg string) {
	return "Subject: " + subject + "\r\n\r\n" + body + "\r\n"
}

func sendMessage(to string, message string) error {
	msg := "From: " + mailConf.From + "\r\n" + "To: " + to + "\r\n" + message
	err := smtp.SendMail(mailConf.Host+":"+mailConf.Port, mailConf.auth, mailConf.From, []string{to}, []byte(msg))
	return err
}
