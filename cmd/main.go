package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/Zzarin/auth/internal/config"
	"github.com/Zzarin/auth/internal/config/env"
	"github.com/Zzarin/auth/internal/handlers"
	"github.com/jackc/pgx/v4/pgxpool"
)

var configPath string

func init() {
	flag.StringVar(&configPath, "config-path", ".env", "path to config file")
}

func main() {
	flag.Parse()
	ctx := context.Background()

	err := config.Load(configPath)
	if err != nil {
		log.Fatalf("config.Load: %v", err)
	}

	grpcConfig, err := env.NewGRPCConfig()
	if err != nil {
		log.Fatalf("NewGRPCConfig: %v", err)
	}

	pgConfig, err := env.NewPGConfig()
	if err != nil {
		log.Fatalf("NewPGConfig: %v", err)
	}

	conn, err := pgxpool.Connect(ctx, pgConfig.GetDSN())
	if err != nil {
		log.Fatalf("db connection: %s", err.Error())
	}
	defer conn.Close()

	server := handlers.NewUserHandler(conn)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	err = server.ListenAndServe(ctx, grpcConfig.GetAddress())
	if err != nil {
		log.Printf("start server: %s", err.Error())
	}
}
