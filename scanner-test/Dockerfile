FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go test ./... && go build -o /scanner ./cmd/server
FROM alpine:3.21
WORKDIR /data
COPY --from=build /scanner /usr/local/bin/scanner
EXPOSE 7001 8080
ENTRYPOINT ["scanner"]
