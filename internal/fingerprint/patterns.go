package fingerprint

import "regexp"

type servicePattern struct {
	service string
	re      *regexp.Regexp
	version *regexp.Regexp // nil if version cannot be extracted from the banner
}

// patterns are matched in order; first match wins.
var patterns = []servicePattern{
	{
		service: "ssh",
		re:      regexp.MustCompile(`^SSH-\d+\.\d+-`),
		version: regexp.MustCompile(`^SSH-\d+\.\d+-(.+?)[\r\n]`),
	},
	{
		service: "http",
		re:      regexp.MustCompile(`(?i)Server:\s*nginx`),
		version: regexp.MustCompile(`(?i)Server:\s*nginx/([^\s\r\n]+)`),
	},
	{
		service: "http",
		re:      regexp.MustCompile(`(?i)Server:\s*Apache`),
		version: regexp.MustCompile(`(?i)Server:\s*Apache/([^\s\r\n]+)`),
	},
	{
		service: "http",
		re:      regexp.MustCompile(`(?i)Server:\s*Caddy`),
		version: regexp.MustCompile(`(?i)Server:\s*Caddy`),
	},
	{
		service: "http",
		re:      regexp.MustCompile(`^HTTP/\d`),
		version: nil,
	},
	{
		service: "smtp",
		re:      regexp.MustCompile(`(?i)^220[\s-].*(smtp|postfix|sendmail|exim|mail)`),
		version: regexp.MustCompile(`^220[\s-](.+?)[\r\n]`),
	},
	{
		service: "ftp",
		re:      regexp.MustCompile(`^220[\s-]`),
		version: regexp.MustCompile(`^220[\s-](.+?)[\r\n]`),
	},
	{
		service: "redis",
		re:      regexp.MustCompile(`(?s)^\+PONG|\*\d+\r\n|\$\d+\r\nredis_version`),
		version: regexp.MustCompile(`redis_version:([^\r\n]+)`),
	},
	{
		service: "postgresql",
		re:      regexp.MustCompile(`^R\x00\x00\x00\x08\x00\x00\x00`),
		version: nil,
	},
	{
		service: "mysql",
		re:      regexp.MustCompile(`(?i).{4}[\x0a].+?(mysql|mariadb)`),
		version: regexp.MustCompile(`(?i)([0-9]+\.[0-9]+\.[0-9]+-?(?:mariadb)?[^\x00]*)`),
	},
	{
		service: "elasticsearch",
		re:      regexp.MustCompile(`"cluster_name"|"tagline"\s*:\s*"You Know`),
		version: regexp.MustCompile(`"number"\s*:\s*"([^"]+)"`),
	},
	{
		service: "memcached",
		re:      regexp.MustCompile(`^(STORED|ERROR|VERSION|CLIENT_ERROR)`),
		version: regexp.MustCompile(`^VERSION (.+?)[\r\n]`),
	},
	{
		service: "rdp",
		re:      regexp.MustCompile(`^\x03\x00`),
		version: nil,
	},
	{
		service: "telnet",
		re:      regexp.MustCompile(`^\xff[\xfb-\xfe]`),
		version: nil,
	},
}

// portHints provides fallback service identification when no banner pattern matches.
var portHints = map[uint16]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	143:   "imap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "smtp",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5672:  "amqp",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

// tlsPorts are ports where a TLS handshake is attempted before banner grab.
var tlsPorts = map[uint16]bool{
	443:  true,
	465:  true,
	636:  true,
	993:  true,
	995:  true,
	8443: true,
	9443: true,
}

// httpProbePorts are ports where an HTTP HEAD probe is sent if no passive banner arrives.
var httpProbePorts = map[uint16]bool{
	80:   true,
	443:  true,
	3000: true,
	5000: true,
	8000: true,
	8080: true,
	8443: true,
	8888: true,
	9000: true,
}
