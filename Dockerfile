# syntax=docker/dockerfile:1

# ---- 构建阶段：纯静态编译（gorm postgres 走 pgx 纯 Go，无需 CGO）----
FROM golang:1.25-alpine AS builder

WORKDIR /src

# 国内服务器走 goproxy.cn（direct 兜底，海外环境亦可用）
ENV GOPROXY=https://goproxy.cn,direct

# 先拉依赖，利用层缓存
COPY go.mod go.sum ./
RUN go mod download

# 再拷源码编译
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

# ---- 运行阶段：精简 alpine，带 ca-certificates 与时区 ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 vulture

WORKDIR /app

# 配置目录（viper 运行时按 APP_ENV 读取 config/config.<env>.yaml）
COPY --from=builder /src/config ./config
COPY --from=builder /out/server ./server

USER vulture

EXPOSE 8080

ENTRYPOINT ["/app/server"]
