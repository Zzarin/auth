package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/Zzarin/auth/internal/handlers"
	"github.com/rs/zerolog/log"
)

const grpcPort = 50051 // TODO get port from config

func main() {
	server := handlers.NewUserHandler()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	err := server.ListenAndServe(ctx, fmt.Sprintf(":%d", grpcPort))
	if err != nil {
		log.Printf("start server: %s", err.Error())
	}
}
