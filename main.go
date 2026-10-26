package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	dataDir := flag.String("data", env("SUBS_DATA_DIR", "./data"), "持久化目录")
	addr := flag.String("listen", env("SUBS_LISTEN", "127.0.0.1:8787"), "监听地址")
	reset := flag.Bool("reset-password", false, "使用 SUBS_ADMIN_PASSWORD 重置管理员密码后退出")
	flag.Parse()
	username := env("SUBS_ADMIN_USER", "admin")
	password := os.Getenv("SUBS_ADMIN_PASSWORD")
	hash := ""
	if password != "" {
		if len(password) < 12 || len(password) > 72 {
			log.Fatal("SUBS_ADMIN_PASSWORD 必须为 12–72 字节")
		}
		b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
		if err != nil {
			log.Fatal("密码哈希失败")
		}
		hash = string(b)
	}
	if checkName(username) != nil {
		log.Fatal("管理员账号格式无效")
	}
	store, err := openStore(*dataDir, username, hash)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	if *reset {
		if hash == "" {
			log.Fatal("请通过 SUBS_ADMIN_PASSWORD 提供新密码")
		}
		if err := store.mutate(func(s *State) error { s.Username = username; s.PasswordHash = hash; return nil }); err != nil {
			log.Fatal("保存新密码失败")
		}
		log.Print("管理员密码已重置，请重启服务使旧会话失效")
		return
	}
	a := newApp(store, newHTTPClient(os.Getenv("SUBS_ALLOW_PRIVATE_UPSTREAM") == "true"))
	a.publicURL = strings.TrimSuffix(os.Getenv("SUBS_PUBLIC_URL"), "/")
	if a.publicURL != "" {
		u, e := url.Parse(a.publicURL)
		if e != nil || u.User != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			log.Fatal("SUBS_PUBLIC_URL 必须是无路径的 HTTP(S) 外部地址")
		}
	}
	a.secureCookie = os.Getenv("SUBS_SECURE_COOKIE") == "true" || strings.HasPrefix(a.publicURL, "https://")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: *addr, Handler: a.handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	go a.scheduler(ctx)
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Subs 已启动：http://%s（数据目录 %s）", *addr, *dataDir)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}
