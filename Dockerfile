FROM golang:1.14 as builder
WORKDIR /app/openvpn-exporter
ADD . /app/openvpn-exporter
RUN apt update && \
    apt install -y upx && \
    go build -ldflags '-s -w -linkmode external -extldflags -static' -o /app/openvpn-exporter/start . && \
    upx -9 start

FROM alpine:3.11 as production
WORKDIR /app
COPY --from=builder /app/openvpn-exporter/start /app/
EXPOSE 9509
ENTRYPOINT ["./start"]
