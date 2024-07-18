LOCAL_BIN:=$(CURDIR)/bin
REMOTE_SERVER:=cloud
SERVICE_BINARY := $(LOCAL_BIN)/api_user_linux
REGESTRY := zarin.cr.cloud.ru
USERNAME := $(REGESTRY_USERNAME)
PASSWORD := $(REGESTRY_PASSWORD)

install-deps:
	GOBIN=$(LOCAL_BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1
	GOBIN=$(LOCAL_BIN) go install -mod=mod google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

get-deps:
	go get -u google.golang.org/protobuf/cmd/protoc-gen-go
	go get -u google.golang.org/grpc/cmd/protoc-gen-go-grpc

install-golangci-lint:
	GOBIN=$(LOCAL_BIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.3

lint:
	./bin/golangci-lint run ./... --config .golangci.pipeline.yaml

generate:
	make generate-auth-api

generate-auth-api:
	mkdir -p pkg/user_v1
	protoc --proto_path api/user_v1 \
	--go_out=pkg/user_v1 --go_opt=paths=source_relative \
	--plugin=protoc-gen-go=bin/protoc-gen-go \
	--go-grpc_out=pkg/user_v1 --go-grpc_opt=paths=source_relative \
	--plugin=protoc-gen-go-grpc=bin/protoc-gen-go-grpc \
	api/user_v1/user.proto

build:
	GOOS=linux GOARCH=amd64 go build -o $(SERVICE_BINARY) cmd/main.go

copy_to_server:
	scp $(SERVICE_BINARY) $(REMOTE_SERVER):

docker_build_and_push:
	docker buildx build --no-cache --platform linux/amd64 -t $(REGESTRY)/api_user:v0.0.1 .
	docker login -u $(REGESTRY_USERNAME) -p $(REGESTRY_PASSWORD) $(REGESTRY)
	docker push $(REGESTRY)/api_user:v0.0.1
