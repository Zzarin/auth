package env

import (
	"errors"
	"os"

	"github.com/Zzarin/auth/internal/config"
)

const (
	dsnEnvName = "PG_DSN"
)

var _ config.DBConfig = (*pgConfig)(nil)

type pgConfig struct {
	dsn string
}

func NewPGConfig() (config.DBConfig, error) {
	dsn := os.Getenv(dsnEnvName)
	if len(dsn) == 0 {
		return nil, errors.New("dsn is empty")
	}

	return &pgConfig{
		dsn: dsn,
	}, nil
}

func (cfg *pgConfig) DSN() string {
	return cfg.dsn
}
