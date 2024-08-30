package config

import (
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

type GRPCConfig interface {
	Address() string
}

type DBConfig interface {
	DSN() string
}

func Load(path string) error {
	if err := godotenv.Load(path); err != nil {
		return errors.Wrap(err, "godotenv.Load")
	}

	return nil
}
