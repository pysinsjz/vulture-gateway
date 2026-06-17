// Command server 是网关 HTTP 服务入口。
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pysinsjz/vulture-gateway/cmd/wire"
	"github.com/pysinsjz/vulture-gateway/config"
	"github.com/pysinsjz/vulture-gateway/internal/db"
)

func main() {
	cfg, err := config.Load(os.Getenv("APP_ENV"))
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}
	log.Printf("vulture-gateway 启动，env=%s addr=%s scaffold=%v", cfg.Env, cfg.Server.Addr, cfg.Scaffold.Enabled)

	app, err := wire.WireApp(cfg)
	if err != nil {
		log.Fatalf("装配失败: %v", err)
	}

	// 启动即校验 Redis 连通性（即时吊销依赖 Redis，ADR-0010）。
	pingCtx, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if err := app.Redis.Ping(pingCtx).Err(); err != nil {
		log.Fatalf("Redis 连接失败 (%s): %v", cfg.Redis.Addr, err)
	}
	log.Printf("Redis 连接就绪 (%s)", cfg.Redis.Addr)

	// 校验 PostgreSQL 连通性并迁移表结构。
	if err := db.Ping(pingCtx, app.DB); err != nil {
		log.Fatalf("PostgreSQL 连接失败: %v", err)
	}
	if err := db.AutoMigrate(app.DB); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}
	log.Println("PostgreSQL 连接就绪、迁移完成")

	srv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           app.Engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务异常退出: %v", err)
		}
	}()
	log.Printf("HTTP 服务监听于 %s", cfg.Server.Addr)

	// 优雅停机。
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("收到停机信号，开始优雅停机…")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("优雅停机失败: %v", err)
	}
	if err := app.Redis.Close(); err != nil {
		log.Printf("关闭 Redis 连接失败: %v", err)
	}
	if sqlDB, err := app.DB.DB(); err == nil {
		_ = sqlDB.Close()
	}
	log.Println("已停机")
}
