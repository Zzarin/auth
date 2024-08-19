#!/bin/bash
source prod.env

export MIGRATION_DSN="host=$POSTGRES_HOST port=$PG_STANDART_PORT dbname=$POSTGRES_DB user=$POSTGRES_USER password=$POSTGRES_PASSWORD sslmode=disable"

sleep 2 && goose -dir "${MIGRATION_DIR}" postgres "${MIGRATION_DSN}" up -v