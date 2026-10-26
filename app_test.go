package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func testApp(t *testing.T) *App {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-only-password"), bcrypt.MinCost)
	s, err := openStore(t.TempDir(), "admin", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return newApp(s, newHTTPClient(true))
}

func TestOfflineSnapshotPersistsThroughFailureAndRestart(t *testing.T) {
	a := testApp(t)
	var fail atomic.Bool
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "disabled", 503)
			return
		}
		fmt.Fprintf(w, "trojan://test-only-password@node.example:443#HongKong")
	}))
	defer upstream.Close()
	if err := a.store.mutate(func(s *State) error {
		s.ACL = fixtureACL()
		s.Sources = []Source{{ID: "source", Name: "Test", URL: upstream.URL, Enabled: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.refreshSource(context.Background(), "source"); err != nil {
		t.Fatal(err)
	}
	c := a.store.snapshot().Collections[0]
	if err := a.publish(c.ID); err != nil {
		t.Fatal(err)
	}
	get := func(app *App, token string) (int, []byte) {
		r := httptest.NewRequest("GET", "/s/"+token+"/mihomo", nil)
		w := httptest.NewRecorder()
		app.handler().ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	code, before := get(a, c.Token)
	if code != 200 {
		t.Fatal("published subscription unavailable")
	}
	fail.Store(true)
	if a.refreshSource(context.Background(), "source") == nil {
		t.Fatal("disabled upstream should fail")
	}
	if err := a.publish(c.ID); err != nil {
		t.Fatal(err)
	}
	upstream.Close()
	count := hits.Load()
	code, after := get(a, c.Token)
	if code != 200 || !bytes.Equal(before, after) || hits.Load() != count {
		t.Fatal("download must serve the last successful local snapshot without contacting upstream")
	}
	if a.store.snapshot().Sources[0].Error == "" {
		t.Fatal("failure must be visible")
	}
	_ = a.store.Close()
	store, err := openStore(a.store.dir, "ignored", "")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	restarted := newApp(store, &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("offline download tried to fetch upstream")
		return nil, fmt.Errorf("offline")
	})})
	code, after = get(restarted, c.Token)
	if code != 200 || !bytes.Equal(before, after) {
		t.Fatal("snapshot lost across restart")
	}
	old := store.snapshot().Collections[0].Publication.Generation
	if err := store.mutate(func(s *State) error { s.ACL = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if restarted.publish(c.ID) == nil {
		t.Fatal("invalid replacement should fail")
	}
	if store.snapshot().Collections[0].Publication.Generation != old {
		t.Fatal("failed build replaced last good publication")
	}
}

func TestAuthCSRFAndSecretBoundaries(t *testing.T) {
	a := testApp(t)
	h := a.handler()
	request := func(method, path string, body any, cookie *http.Cookie, csrf, origin string) *httptest.ResponseRecorder {
		var b io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			b = bytes.NewReader(raw)
		}
		r := httptest.NewRequest(method, path, b)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if request("GET", "/api/state", nil, nil, "", "").Code != 401 {
		t.Fatal("admin API is public")
	}
	login := request("POST", "/api/login", map[string]string{"username": "admin", "password": "test-only-password"}, nil, "", "")
	if login.Code != 200 {
		t.Fatal("login failed")
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	cookie := cookies[0]
	var session map[string]string
	_ = json.Unmarshal(login.Body.Bytes(), &session)
	body := map[string]any{"name": "源", "url": "https://source.example/sub?token=private-source-secret", "enabled": true}
	if request("POST", "/api/sources", body, cookie, "", "").Code != 403 {
		t.Fatal("CSRF missing was accepted")
	}
	if request("POST", "/api/sources", body, cookie, session["csrf"], "https://attacker.example").Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	if request("POST", "/api/sources", body, cookie, session["csrf"], "").Code != 200 {
		t.Fatal("authorized source creation failed")
	}
	view := request("GET", "/api/state", nil, cookie, "", "")
	if strings.Contains(view.Body.String(), "passwordHash") || strings.Contains(view.Body.String(), "\"cache\"") {
		t.Fatal("internal credentials/cache exposed by status DTO")
	}
	if request("GET", "/s/wrong-token/mihomo", nil, nil, "", "").Code != 404 {
		t.Fatal("unpublished subscription accessible")
	}
	if request("POST", "/api/logout", map[string]any{}, cookie, session["csrf"], "").Code != 200 {
		t.Fatal("logout failed")
	}
	if request("GET", "/api/state", nil, cookie, "", "").Code != 401 {
		t.Fatal("logout did not revoke session")
	}
	for i := 0; i < 9; i++ {
		res := request("POST", "/api/login", map[string]string{"username": "admin", "password": "incorrect"}, nil, "", "")
		if i == 8 && res.Code != 429 {
			t.Fatal("login rate limit missing")
		}
	}
}

func TestURLAndNetworkBoundary(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "http://user:password@example.com", "https://example.com/#fragment", "http:///missing"} {
		if validateURL(u) == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("private endpoint must not be reached") }))
	defer s.Close()
	if _, err := fetch(context.Background(), newHTTPClient(false), s.URL); err == nil || !strings.Contains(err.Error(), "SUBS_ALLOW_PRIVATE_UPSTREAM") {
		t.Fatal("private upstream must require explicit opt-in with actionable diagnostics")
	}
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "240.1.2.3", "2001:db8::1"} {
		if !privateIP(netip.MustParseAddr(ip)) {
			t.Fatal("non-public address accepted")
		}
	}
	if privateIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address rejected")
	}
}

func TestStoreLockAndFailedWriteRollback(t *testing.T) {
	a := testApp(t)
	if _, err := openStore(a.store.dir, "admin", ""); err == nil {
		t.Fatal("two writers acquired the same data directory")
	}
	p := filepath.Join(a.store.dir, "state.json")
	backup := p + ".backup"
	if err := os.Rename(p, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	old := a.store.snapshot().Username
	if err := a.store.mutate(func(s *State) error { s.Username = "changed"; return nil }); err == nil {
		t.Fatal("failing disk write should return error")
	}
	if a.store.snapshot().Username != old {
		t.Fatal("failed transaction changed memory state")
	}
	_ = os.Remove(p)
	_ = os.Rename(backup, p)
}

func TestPerFormatFallbackAndUnavailableFirstExport(t *testing.T) {
	a := testApp(t)
	if err := a.store.mutate(func(s *State) error {
		s.ACL = fixtureACL()
		s.Sources = []Source{{ID: "s", Name: "Source", Enabled: true, Cache: []Proxy{{"name": "Old Trojan", "type": "trojan", "server": "old.example", "port": 443, "password": "test"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := a.store.snapshot().Collections[0]
	if err := a.publish(c.ID); err != nil {
		t.Fatal(err)
	}
	old := a.store.snapshot().Collections[0].Publication
	oldBody, err := os.ReadFile(filepath.Join(a.store.dir, "snapshots", c.ID, old.Generation, "clash.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.mutate(func(s *State) error {
		s.Sources[0].Cache = []Proxy{{"name": "New VLESS", "type": "vless", "server": "new.example", "port": 443, "uuid": testUUID}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.publish(c.ID); err != nil {
		t.Fatal(err)
	}
	next := a.store.snapshot().Collections[0].Publication
	if next.Artifacts["clash"].Error == "" || next.Artifacts["clash"].SHA256 != old.Artifacts["clash"].SHA256 || next.Artifacts["mihomo"].SHA256 == old.Artifacts["mihomo"].SHA256 {
		t.Fatal("format-specific failure must retain that format and update supported formats")
	}
	b, err := os.ReadFile(filepath.Join(a.store.dir, "snapshots", c.ID, next.Generation, "clash.yaml"))
	if err != nil || !bytes.Equal(b, oldBody) {
		t.Fatal("old legacy artifact lost")
	}
	if err := a.store.mutate(func(s *State) error {
		s.Collections = append(s.Collections, Collection{ID: "new", Name: "New", AllSources: true, Token: randomToken(24)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.publish("new"); err != nil {
		t.Fatal(err)
	}
	pub := a.store.snapshot().Collections[1].Publication
	if pub.Artifacts["clash"].Error == "" || pub.Artifacts["clash"].SHA256 != "" || pub.Artifacts["mihomo"].SHA256 == "" {
		t.Fatal("unsupported first export must be clearly unavailable without blocking supported formats")
	}
}
