package mail

import (
	"fmt"
	"log/slog"
	"net/smtp"
	"os"
)

// Sender interface defines the required email notification methods.
type Sender interface {
	SendReceipt(toEmail, amount, plan, reference string) error
	SendUpgradeWelcome(toEmail string) error
	SendReminder(toEmail string) error
	SendPasswordReset(toEmail, resetURL string) error
	Close()
}

type emailJob struct {
	To      string
	Subject string
	Body    string
}

// SMTPSender implements a high-performance email sender using a worker pool.
type SMTPSender struct {
	log      *slog.Logger
	jobs     chan emailJob
	host     string
	port     string
	user     string
	password string
	from     string
	workers  int
}

// New creates a new Sender. If SMTP_HOST is not configured, it falls back to a console logger.
func New(log *slog.Logger) Sender {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		host = "smtp.gmail.com" // Google SMTP by default based on config
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	user := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")
	from := os.Getenv("SMTP_FROM")
	if from == "" {
		from = "billing@corvus.sh"
	}

	if user == "" || password == "" {
		log.Warn("SMTP credentials missing, falling back to Console Logger. Set SMTP_USER and SMTP_PASS to enable Google SMTP.")
		return &ConsoleSender{log: log}
	}

	s := &SMTPSender{
		log:      log,
		jobs:     make(chan emailJob, 1000), // Buffer up to 1000 emails
		host:     host,
		port:     port,
		user:     user,
		password: password,
		from:     from,
		workers:  5, // Concurrency pool size
	}

	// Start worker pool
	for i := 0; i < s.workers; i++ {
		go s.worker(i)
	}

	return s
}

func (s *SMTPSender) worker(id int) {
	auth := smtp.PlainAuth("", s.user, s.password, s.host)
	addr := s.host + ":" + s.port

	for job := range s.jobs {
		msg := []byte(fmt.Sprintf("To: %s\r\n"+
			"From: %s\r\n"+
			"Subject: %s\r\n"+
			"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"+
			"%s\r\n", job.To, s.from, job.Subject, job.Body))

		err := smtp.SendMail(addr, auth, s.from, []string{job.To}, msg)
		if err != nil {
			s.log.Error("failed to send email", "worker", id, "to", job.To, "err", err)
		} else {
			s.log.Info("email sent successfully", "worker", id, "to", job.To, "subject", job.Subject)
		}
	}
}

func (s *SMTPSender) Close() {
	close(s.jobs)
}

func (s *SMTPSender) SendReceipt(toEmail, amount, plan, reference string) error {
	body := fmt.Sprintf(`
	<div style="font-family: monospace; padding: 20px; background-color: #111318; color: #fff;">
		<h2 style="color: #F97316;">Corvus Intelligence</h2>
		<p>Thank you for your payment.</p>
		<p><strong>Plan:</strong> %s</p>
		<p><strong>Amount:</strong> %s</p>
		<p><strong>Reference:</strong> %s</p>
		<p>Your account is now active. If you have any issues, reply to this email.</p>
	</div>
	`, plan, amount, reference)

	select {
	case s.jobs <- emailJob{To: toEmail, Subject: "Your Corvus Receipt", Body: body}:
		return nil
	default:
		return fmt.Errorf("email worker queue is full")
	}
}

func (s *SMTPSender) SendUpgradeWelcome(toEmail string) error {
	body := `
	<div style="font-family: monospace; padding: 20px; background-color: #111318; color: #fff;">
		<h2 style="color: #F97316;">Welcome to Corvus Pro</h2>
		<p>Your account has been upgraded. You now have access to:</p>
		<ul>
			<li>Unlimited Scans & Retention</li>
			<li>CVE + OSV Correlation</li>
			<li>Full API Access</li>
		</ul>
		<p>Head over to the dashboard to start exploring your network.</p>
	</div>
	`
	select {
	case s.jobs <- emailJob{To: toEmail, Subject: "Welcome to Corvus Pro", Body: body}:
		return nil
	default:
		return fmt.Errorf("email worker queue is full")
	}
}

func (s *SMTPSender) SendPasswordReset(toEmail, resetURL string) error {
	body := fmt.Sprintf(`
	<div style="font-family: monospace; padding: 20px; background-color: #111318; color: #fff;">
		<h2 style="color: #F97316;">Reset your Corvus password</h2>
		<p>We received a request to reset the password for this account.</p>
		<p style="margin: 24px 0;">
			<a href="%s" style="background-color: #F97316; color: #0c0d10; padding: 12px 24px; text-decoration: none; font-weight: bold; letter-spacing: 1px; text-transform: uppercase; font-size: 12px;">Reset password</a>
		</p>
		<p style="color: #888; font-size: 12px;">This link expires in 30 minutes. If you didn't request this, you can safely ignore this email — your password won't change.</p>
		<p style="color: #555; font-size: 11px;">Or paste this link into your browser:<br>%s</p>
	</div>
	`, resetURL, resetURL)

	select {
	case s.jobs <- emailJob{To: toEmail, Subject: "Reset your Corvus password", Body: body}:
		return nil
	default:
		return fmt.Errorf("email worker queue is full")
	}
}

func (s *SMTPSender) SendReminder(toEmail string) error {
	body := `
	<div style="font-family: monospace; padding: 20px; background-color: #111318; color: #fff;">
		<h2 style="color: #F97316;">Subscription Renewal Notice</h2>
		<p>Your Corvus Pro subscription is set to renew soon.</p>
		<p>Manage your billing preferences in the dashboard.</p>
	</div>
	`
	select {
	case s.jobs <- emailJob{To: toEmail, Subject: "Corvus Subscription Renewal", Body: body}:
		return nil
	default:
		return fmt.Errorf("email worker queue is full")
	}
}

// ConsoleSender remains for local development without SMTP credentials.
type ConsoleSender struct {
	log *slog.Logger
}

func (s *ConsoleSender) Close() {}

func (s *ConsoleSender) SendReceipt(toEmail, amount, plan, reference string) error {
	s.log.Info("MOCK EMAIL SENT", "to", toEmail, "subject", "Your Corvus Receipt")
	return nil
}

func (s *ConsoleSender) SendUpgradeWelcome(toEmail string) error {
	s.log.Info("MOCK EMAIL SENT", "to", toEmail, "subject", "Welcome to Corvus Pro")
	return nil
}

func (s *ConsoleSender) SendReminder(toEmail string) error {
	s.log.Info("MOCK EMAIL SENT", "to", toEmail, "subject", "Subscription Reminder")
	return nil
}

func (s *ConsoleSender) SendPasswordReset(toEmail, resetURL string) error {
	// In dev (no SMTP), log the link so it can be copied straight from the console.
	s.log.Info("MOCK EMAIL SENT", "to", toEmail, "subject", "Reset your Corvus password", "reset_url", resetURL)
	return nil
}
