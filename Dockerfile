FROM golang:1.20.3-alpine as builder

WORKDIR /source
COPY . .

RUN go mod download
RUN go build -o api_user cmd/main.go

FROM alpine:latest

WORKDIR /root/
COPY --from=builder /source/api_user .
COPY local.env .
COPY prod.env .

CMD [ "./api_user", "-config-path=prod.env"]