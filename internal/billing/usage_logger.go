package billing

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// DBUsageLogger satisfies engine.UsageLogger using the billing DB.
type DBUsageLogger struct{ db *sql.DB }

func NewDBUsageLogger(db *sql.DB) *DBUsageLogger { return &DBUsageLogger{db: db} }

func (l *DBUsageLogger) LogScan(userID string) {
	_, _ = l.db.Exec(
		`INSERT INTO usage_logs (id, user_id, feature, created_at) VALUES ($1, $2, 'scan', $3)`,
		uuid.New().String(), userID, time.Now(),
	)
}
