package mail

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

type Mail struct {
	senderId string
	toIds    []string
	subject  string
	body     string
}

type SmtpServer struct {
	host string
	port string
}

func (s *SmtpServer) ServerName() string {
	return s.host + ":" + s.port
}

func (mail *Mail) BuildMessage() string {
	message := ""
	message += fmt.Sprintf("From: %s\r\n", mail.senderId)
	if len(mail.toIds) > 0 {
		message += fmt.Sprintf("To: %s\r\n", strings.Join(mail.toIds, ";"))
	}

	message += fmt.Sprintf("Subject: %s\r\n", mail.subject)
	message += "\r\n" + mail.body

	return message
}

func SendMailToUser(fromEmail string, toEmail string, password string, subject string, body string) error {
	mail := Mail{}
	mail.senderId = fromEmail
	mail.toIds = []string{toEmail}
	mail.subject = subject
	mail.body = body

	messageBody := mail.BuildMessage()

	smtpServer := SmtpServer{host: "smtp.zoho.com", port: "465"}

	log.Println(smtpServer.host)

	//build an auth
	auth := smtp.PlainAuth("", mail.senderId, password, smtpServer.host)

	// Gmail will reject connection if it's not secure
	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpServer.host,
	}

	conn, err := tls.Dial("tcp", smtpServer.ServerName(), tlsconfig)
	if err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	client, err := smtp.NewClient(conn, smtpServer.host)
	if err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	// step 1: Use Auth
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	// step 2: add all from and to
	if err = client.Mail(mail.senderId); err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}
	for _, k := range mail.toIds {
		if err = client.Rcpt(k); err != nil {
			return fmt.Errorf("Could not send mail: %v", err)
		}
	}

	// Data
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	_, err = w.Write([]byte(messageBody))
	if err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("Could not send mail: %v", err)
	}

	client.Quit()

	return nil
}
