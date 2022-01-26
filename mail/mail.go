package mail

import (
	"net/smtp"
)

type Config struct {
	from     string
	password string
	host     string
	port     string
	auth     smtp.Auth
}

var config = &Config{}

func InitSmtp(from string, pass string, host string, port string) {
	config.from = from
	config.password = pass
	config.host = host
	config.port = port
	config.auth = smtp.PlainAuth("", from, pass, host)
}

func GenMessage(subject string, body string) (msg string) {
	return "Subject: " + subject + "\r\n\r\n" + body + "\r\n"
}

func Send(to string, message string) error {
	msg := "From: " + config.from + "\r\n" + "To: " + to + "\r\n" + message
	err := smtp.SendMail(config.host+":"+config.port, config.auth, config.from, []string{to}, []byte(msg))
	return err
}
