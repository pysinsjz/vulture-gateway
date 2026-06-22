// Package notify 提供验证码外发渠道（邮件/短信）的抽象与实现（ADR-0013）。
package notify

import (
	"context"
	"fmt"
	"log"
	"net/smtp"
	"strconv"
)

// CodeSender 抽象「向某标识发送一枚验证码」。邮件与短信渠道各实现一份。
type CodeSender interface {
	SendCode(ctx context.Context, dest, code string) error
}

// StubSender 仅把验证码记录到日志，供无真实 SMTP/短信凭据时的本地/CI 联调（ADR-0013 stub 顶替）。
// 生产严禁使用：会把验证码暴露到日志。
type StubSender struct {
	channel string
}

// NewStubSender 构造桩发送器。
func NewStubSender(channel string) *StubSender {
	return &StubSender{channel: channel}
}

func (s *StubSender) SendCode(_ context.Context, dest, code string) error {
	log.Printf("[otp-stub:%s] dest=%s code=%s（桩发送器，仅供联调）", s.channel, dest, code)
	return nil
}

// SMTPSender 经 SMTP 发送邮件验证码。凭据来自 provider seed（host/port/username/password）。
type SMTPSender struct {
	host     string
	port     int
	username string
	password string
	from     string
}

// NewSMTPSender 构造 SMTP 邮件发送器。
func NewSMTPSender(host string, port int, username, password, from string) *SMTPSender {
	return &SMTPSender{host: host, port: port, username: username, password: password, from: from}
}

func (s *SMTPSender) SendCode(_ context.Context, dest, code string) error {
	addr := s.host + ":" + strconv.Itoa(s.port)
	auth := smtp.PlainAuth("", s.username, s.password, s.host)
	msg := []byte("To: " + dest + "\r\n" +
		"From: " + s.from + "\r\n" +
		"Subject: 登录验证码\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"您的登录验证码是 " + code + "，5 分钟内有效。请勿向他人泄露。\r\n")
	if err := smtp.SendMail(addr, auth, s.from, []string{dest}, msg); err != nil {
		return fmt.Errorf("SMTP 发送邮件失败: %w", err)
	}
	return nil
}
