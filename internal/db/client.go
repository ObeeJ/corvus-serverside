package db

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Client wraps the PostgreSQL connection pool.
type Client struct {
	DB  *sql.DB
	log *slog.Logger
}

// New connects to PostgreSQL and runs pending migrations.
func New(connString string, log *slog.Logger) (*Client, error) {
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, fmt.Errorf("connecting to db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("pinging db: %w", err)
	}

	log.Info("Connected to PostgreSQL")

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	log.Info("Database migrations applied successfully")

	return &Client{DB: db, log: log}, nil
}

// Close closes the database pool.
func (c *Client) Close() error {
	return c.DB.Close()
}

func runMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", driver)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}
