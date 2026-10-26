package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web/*
var webFiles embed.FS

type session struct {
	Expires time.Time
	CSRF    string
}
type attempts struct {
	Count int
	Since time.Time
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("请求必须使用 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return errors.New("请求数据格式无效或过大")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("请求只能包含一个 JSON 对象")
	}
	return nil
}

func sessionKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (a *App) cookieSecure(r *http.Request) bool {
	return a.secureCookie || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
func (a *App) getSession(r *http.Request) (session, bool) {
	c, err := r.Cookie("subs_session")
	if err != nil {
		return session{}, false
	}
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	key := sessionKey(c.Value)
	s, ok := a.sessions[key]
	if !ok {
		return s, false
	}
	if time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return session{}, false
	}
	return s, true
}

func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host == r.Host
	}
	return true
}

func (a *App) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.getSession(r)
		if !ok {
			apiError(w, 401, "请先登录")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !sameOrigin(r) || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
				apiError(w, 403, "请求校验失败，请刷新页面后重试")
				return
			}
		}
		next(w, r)
	}
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiError(w, 403, "不允许跨站登录")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	a.sessionMu.Lock()
	now := time.Now()
	for k, v := range a.loginAttempts {
		if now.Sub(v.Since) > 10*time.Minute {
			delete(a.loginAttempts, k)
		}
	}
	v := a.loginAttempts[ip]
	if v.Since.IsZero() {
		v.Since = now
	}
	if v.Count >= 8 || len(a.loginAttempts) > 4096 {
		a.sessionMu.Unlock()
		w.Header().Set("Retry-After", "600")
		apiError(w, 429, "登录尝试过多，请 10 分钟后重试")
		return
	}
	v.Count++
	a.loginAttempts[ip] = v
	a.sessionMu.Unlock()
	select {
	case a.loginSlots <- struct{}{}:
		defer func() { <-a.loginSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		apiError(w, 429, "登录请求繁忙，请稍后重试")
		return
	}
	s := a.store.snapshot()
	err := bcrypt.CompareHashAndPassword([]byte(s.PasswordHash), []byte(in.Password))
	if len(in.Password) > 72 || len(in.Username) > 256 || err != nil || subtle.ConstantTimeCompare([]byte(in.Username), []byte(s.Username)) != 1 {
		apiError(w, 401, "账号或密码不正确")
		return
	}
	token := randomToken(32)
	sess := session{Expires: now.Add(12 * time.Hour), CSRF: randomToken(24)}
	a.store.mu.RLock()
	if a.store.state.PasswordHash != s.PasswordHash || a.store.state.Username != s.Username {
		a.store.mu.RUnlock()
		apiError(w, 401, "账号已变更，请重新登录")
		return
	}
	a.sessionMu.Lock()
	delete(a.loginAttempts, ip)
	for k, v := range a.sessions {
		if now.After(v.Expires) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 128 {
		a.sessionMu.Unlock()
		a.store.mu.RUnlock()
		apiError(w, 429, "活动会话过多，请稍后重试")
		return
	}
	if c, err := r.Cookie("subs_session"); err == nil {
		delete(a.sessions, sessionKey(c.Value))
	}
	a.sessions[sessionKey(token)] = sess
	a.sessionMu.Unlock()
	a.store.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{Name: "subs_session", Value: token, Path: "/", HttpOnly: true, Secure: a.cookieSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	writeJSON(w, 200, map[string]any{"username": s.Username, "csrf": sess.CSRF})
}

func (a *App) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("GET /api/session", a.protected(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.getSession(r)
		writeJSON(w, 200, map[string]string{"username": a.store.snapshot().Username, "csrf": s.CSRF})
	}))
	m.HandleFunc("POST /api/logout", a.protected(func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("subs_session"); e == nil {
			a.sessionMu.Lock()
			delete(a.sessions, sessionKey(c.Value))
			a.sessionMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "subs_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.cookieSecure(r), SameSite: http.SameSiteStrictMode})
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	m.HandleFunc("GET /api/state", a.protected(a.stateView))
	m.HandleFunc("POST /api/sources", a.protected(a.saveSource))
	m.HandleFunc("PUT /api/sources/{id}", a.protected(a.saveSource))
	m.HandleFunc("DELETE /api/sources/{id}", a.protected(a.deleteSource))
	m.HandleFunc("POST /api/sources/{id}/refresh", a.protected(a.refreshHandler))
	m.HandleFunc("POST /api/refresh", a.protected(a.refreshHandler))
	m.HandleFunc("POST /api/rules/refresh", a.protected(a.rulesHandler))
	m.HandleFunc("POST /api/collections", a.protected(a.saveCollection))
	m.HandleFunc("PUT /api/collections/{id}", a.protected(a.saveCollection))
	m.HandleFunc("DELETE /api/collections/{id}", a.protected(a.deleteCollection))
	m.HandleFunc("POST /api/collections/{id}/build", a.protected(a.buildHandler))
	m.HandleFunc("POST /api/collections/{id}/rotate", a.protected(a.rotateToken))
	m.HandleFunc("PUT /api/settings", a.protected(a.settingsHandler))
	m.HandleFunc("POST /api/password", a.protected(a.passwordHandler))
	m.HandleFunc("GET /s/{token}/{format}", a.download)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { apiError(w, 404, "接口不存在") })
	assets, _ := fs.Sub(webFiles, "web")
	fileServer := http.FileServer(http.FS(assets))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/" && r.URL.Path != "/app.js" && r.URL.Path != "/style.css" {
			http.NotFound(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		m.ServeHTTP(w, r)
	})
}

func (a *App) stateView(w http.ResponseWriter, r *http.Request) {
	s := a.store.snapshot()
	sources := []map[string]any{}
	for _, v := range s.Sources {
		protocols := map[string]int{}
		for _, p := range v.Cache {
			protocols[text(p, "type")]++
		}
		sources = append(sources, map[string]any{"id": v.ID, "name": v.Name, "url": v.URL, "enabled": v.Enabled, "nodes": len(v.Cache), "protocols": protocols, "updatedAt": v.UpdatedAt, "attemptedAt": v.AttemptedAt, "error": v.Error, "warnings": v.Warnings})
	}
	var acl any
	if s.ACL != nil {
		acl = map[string]any{"rules": len(s.ACL.Rules), "groups": len(s.ACL.Groups), "lists": s.ACL.Lists, "updatedAt": s.ACL.UpdatedAt}
	}
	writeJSON(w, 200, map[string]any{"username": s.Username, "sources": sources, "collections": s.Collections, "acl": acl, "ruleAttemptedAt": s.RuleAttemptedAt, "ruleError": s.RuleError, "settings": s.Settings, "publicUrl": a.publicURL})
}

func (a *App) mutateHandler(w http.ResponseWriter, fn func(*State) error) {
	if !a.updateMu.TryLock() {
		apiError(w, 409, "更新正在进行，请完成后重试")
		return
	}
	defer a.updateMu.Unlock()
	if err := a.store.mutate(fn); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) saveSource(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.URL = strings.TrimSpace(in.URL)
	if err := checkName(in.Name); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if err := validateURL(in.URL); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	a.mutateHandler(w, func(s *State) error {
		id := r.PathValue("id")
		i := sourceIndex(s, id)
		for _, v := range s.Sources {
			if v.URL == in.URL && v.ID != id {
				return errors.New("该地址已存在")
			}
		}
		if id == "" {
			if len(s.Sources) >= 100 {
				return errors.New("最多添加 100 个源")
			}
			s.Sources = append(s.Sources, Source{ID: randomToken(8), Name: in.Name, URL: in.URL, Enabled: in.Enabled})
			return nil
		}
		if i < 0 {
			return errors.New("订阅源不存在")
		}
		v := &s.Sources[i]
		if v.URL != in.URL {
			v.Error = "地址已更改，仍保留上一次缓存，更新成功后替换"
			v.AttemptedAt = time.Time{}
		}
		v.Name = in.Name
		v.URL = in.URL
		v.Enabled = in.Enabled
		return nil
	})
}

func (a *App) deleteSource(w http.ResponseWriter, r *http.Request) {
	a.mutateHandler(w, func(s *State) error {
		i := sourceIndex(s, r.PathValue("id"))
		if i < 0 {
			return errors.New("订阅源不存在")
		}
		s.Sources = slices.Delete(s.Sources, i, i+1)
		for i := range s.Collections {
			s.Collections[i].SourceIDs = slices.DeleteFunc(s.Collections[i].SourceIDs, func(id string) bool { return id == r.PathValue("id") })
		}
		return nil
	})
}

func (a *App) saveCollection(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string   `json:"name"`
		AllSources bool     `json:"allSources"`
		SourceIDs  []string `json:"sourceIds"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if err := checkName(in.Name); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	a.mutateHandler(w, func(s *State) error {
		if !in.AllSources && len(in.SourceIDs) == 0 {
			return errors.New("至少选择一个源，或使用全部启用源")
		}
		seen := map[string]bool{}
		for _, id := range in.SourceIDs {
			if sourceIndex(s, id) < 0 || seen[id] {
				return errors.New("订阅源选择无效")
			}
			seen[id] = true
		}
		id := r.PathValue("id")
		i := collectionIndex(s, id)
		if id == "" {
			if len(s.Collections) >= 50 {
				return errors.New("最多创建 50 个集合")
			}
			s.Collections = append(s.Collections, Collection{ID: randomToken(8), Name: in.Name, AllSources: in.AllSources, SourceIDs: in.SourceIDs, Token: randomToken(24)})
			return nil
		}
		if i < 0 {
			return errors.New("订阅集合不存在")
		}
		s.Collections[i].Name = in.Name
		s.Collections[i].AllSources = in.AllSources
		s.Collections[i].SourceIDs = in.SourceIDs
		return nil
	})
}
func (a *App) deleteCollection(w http.ResponseWriter, r *http.Request) {
	a.mutateHandler(w, func(s *State) error {
		i := collectionIndex(s, r.PathValue("id"))
		if i < 0 {
			return errors.New("订阅集合不存在")
		}
		s.Collections = slices.Delete(s.Collections, i, i+1)
		return nil
	})
}
func (a *App) rotateToken(w http.ResponseWriter, r *http.Request) {
	a.mutateHandler(w, func(s *State) error {
		i := collectionIndex(s, r.PathValue("id"))
		if i < 0 {
			return errors.New("订阅集合不存在")
		}
		s.Collections[i].Token = randomToken(24)
		return nil
	})
}

func (a *App) refreshHandler(w http.ResponseWriter, r *http.Request) {
	if !a.updateMu.TryLock() {
		apiError(w, 409, "已有更新任务正在进行")
		return
	}
	defer a.updateMu.Unlock()
	s := a.store.snapshot()
	if id := r.PathValue("id"); id != "" && sourceIndex(&s, id) < 0 {
		apiError(w, 404, "订阅源不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	writeJSON(w, 200, a.runRefresh(ctx, r.PathValue("id"), r.PathValue("id") == ""))
}
func (a *App) rulesHandler(w http.ResponseWriter, r *http.Request) {
	if !a.updateMu.TryLock() {
		apiError(w, 409, "已有更新任务正在进行")
		return
	}
	defer a.updateMu.Unlock()
	if err := a.refreshRules(r.Context()); err != nil {
		apiError(w, 502, err.Error())
		return
	}
	failures := a.publishAll()
	writeJSON(w, 200, map[string]any{"ok": true, "errors": failures})
}
func (a *App) buildHandler(w http.ResponseWriter, r *http.Request) {
	if !a.updateMu.TryLock() {
		apiError(w, 409, "已有更新任务正在进行")
		return
	}
	defer a.updateMu.Unlock()
	if err := a.publish(r.PathValue("id")); err != nil {
		apiError(w, 422, err.Error())
		return
	}
	s := a.store.snapshot()
	i := collectionIndex(&s, r.PathValue("id"))
	var warnings []string
	if i >= 0 && s.Collections[i].Publication != nil {
		for format, meta := range s.Collections[i].Publication.Artifacts {
			if meta.Error != "" {
				warnings = append(warnings, format+"："+meta.Error)
			}
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "warnings": warnings})
}
func (a *App) settingsHandler(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if err := decodeJSON(w, r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	if (in.SourceIntervalMinutes != 0 && in.SourceIntervalMinutes < 5) || in.SourceIntervalMinutes > 10080 || in.RuleIntervalHours < 1 || in.RuleIntervalHours > 720 {
		apiError(w, 400, "源更新可设 0（仅手动）或 5–10080 分钟，规则更新为 1–720 小时")
		return
	}
	a.mutateHandler(w, func(s *State) error { s.Settings = in; return nil })
}
func (a *App) passwordHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Old string `json:"oldPassword"`
		New string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		apiError(w, 400, err.Error())
		return
	}
	s := a.store.snapshot()
	if bcrypt.CompareHashAndPassword([]byte(s.PasswordHash), []byte(in.Old)) != nil {
		apiError(w, 400, "当前密码不正确")
		return
	}
	if len(in.New) < 12 || len(in.New) > 72 {
		apiError(w, 400, "新密码须为 12–72 字节")
		return
	}
	b, err := bcrypt.GenerateFromPassword([]byte(in.New), 12)
	if err != nil {
		apiError(w, 500, "密码处理失败")
		return
	}
	if err := a.store.mutate(func(s *State) error { s.PasswordHash = string(b); return nil }); err != nil {
		apiError(w, 500, "保存密码失败")
		return
	}
	a.sessionMu.Lock()
	a.sessions = map[string]session{}
	a.sessionMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *App) download(w http.ResponseWriter, r *http.Request) {
	format := r.PathValue("format")
	filename, ok := formatFiles[format]
	if !ok {
		http.NotFound(w, r)
		return
	}
	a.store.mu.RLock()
	var file *os.File
	var artifact Artifact
	var built time.Time
	for _, c := range a.store.state.Collections {
		if subtle.ConstantTimeCompare([]byte(c.Token), []byte(r.PathValue("token"))) == 1 && c.Publication != nil {
			artifact = c.Publication.Artifacts[format]
			built = artifact.UpdatedAt
			file, _ = os.Open(filepath.Join(a.store.dir, "snapshots", c.ID, c.Publication.Generation, filename))
			break
		}
	}
	a.store.mu.RUnlock()
	if file == nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if format == "mihomo" || format == "clash" {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
	w.Header().Set("profile-update-interval", "6")
	http.ServeContent(w, r, filename, built, file)
}
