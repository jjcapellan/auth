package auth

import (
	"net/smtp"
)

type MailConfig struct {
	from     string
	password string
	host     string
	port     string
	auth     smtp.Auth
}

type SmtpConfig struct {
	From     string
	Password string
	Host     string
	Port     string
}

var mailConfig = &MailConfig{}

func InitSmtp(from string, pass string, host string, port string) {
	mailConfig.from = from
	mailConfig.password = pass
	mailConfig.host = host
	mailConfig.port = port
	mailConfig.auth = smtp.PlainAuth("", from, pass, host)
}

func GenMessage(subject string, body string) (msg string) {
	return "Subject: " + subject + "\r\n\r\n" + body + "\r\n"
}

func Send(to string, message string) error {
	msg := "From: " + mailConfig.from + "\r\n" + "To: " + to + "\r\n" + message
	err := smtp.SendMail(mailConfig.host+":"+mailConfig.port, mailConfig.auth, mailConfig.from, []string{to}, []byte(msg))
	return err
}
