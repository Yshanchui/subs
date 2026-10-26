package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const testUUID = "00000000-0000-4000-8000-000000000001"

func TestURIProtocols(t *testing.T) {
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "日本 VMess", "add": "node.example", "port": "443", "id": testUUID, "aid": "0", "net": "ws", "tls": "tls", "host": "edge.example", "path": "/ws"})
	ssr := base64.RawURLEncoding.EncodeToString([]byte("node.example:443:auth_sha1_v4:aes-128-cfb:tls1.2_ticket_auth:" + base64.RawURLEncoding.EncodeToString([]byte("test-password")) + "/?remarks=" + base64.RawURLEncoding.EncodeToString([]byte("SSR test"))))
	cases := map[string]string{
		"ss":        "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:test-password")) + "@node.example:443#香港",
		"ssr":       "ssr://" + ssr,
		"vmess":     "vmess://" + base64.StdEncoding.EncodeToString(vm),
		"vless":     "vless://" + testUUID + "@node.example:443?security=reality&pbk=test-public-key&sid=12&flow=xtls-rprx-vision&fp=chrome#VLESS",
		"trojan":    "trojan://test-password@node.example:443?sni=edge.example&type=ws&host=edge.example&path=%2Fws#Trojan",
		"hysteria2": "hy2://test-password@node.example:443?sni=edge.example&obfs=salamander&obfs-password=test-obfs&mport=443-500#HY2",
		"tuic":      "tuic://" + testUUID + ":test-password@node.example:443?congestion_control=bbr&alpn=h3#TUIC",
		"socks5":    "socks5://user:password@node.example:1080#SOCKS",
	}
	for typ, uri := range cases {
		t.Run(typ, func(t *testing.T) {
			for _, raw := range []string{uri, base64.StdEncoding.EncodeToString([]byte(uri))} {
				nodes, _, err := parseSubscription([]byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				if len(nodes) != 1 || text(nodes[0], "type") != typ {
					t.Fatal("protocol not preserved")
				}
				nodes[0]["name"] = "聚合 · 新名称"
				out, err := proxyURI(nodes[0])
				if err != nil {
					t.Fatal(err)
				}
				parsed, _, err := parseSubscription([]byte(out))
				if err != nil {
					t.Fatal(err)
				}
				if text(parsed[0], "name") != "聚合 · 新名称" {
					t.Fatal("name not updated")
				}
				if text(parsed[0], "server") != "node.example" {
					t.Fatal("endpoint changed")
				}
			}
		})
	}
}

func TestYAMLAndInvalidSource(t *testing.T) {
	data := `proxies:
  - {name: 'Traffic: 1 GB', type: trojan, server: node.example, port: 443, password: test}
  - {name: '香港节点', type: trojan, server: node.example, port: 443, password: test, __uri: 'bad://injected'}
  - {name: 'HY2', type: hysteria2, server: hy.example, port: 443, password: test, ports: '443-500'}
`
	n, w, e := parseSubscription([]byte(data))
	if e != nil {
		t.Fatal(e)
	}
	if len(n) != 2 || len(w) != 1 || n[0]["__uri"] != nil {
		t.Fatal("metadata and internal keys must be removed")
	}
	for _, bad := range []string{"<html>login required</html>", "proxies: []", "proxies: [{name: bad, type: trojan, port: 443}]", "vless://bad@host.example:443", "trojan://x@host.example:99999", "anytls://x@host.example:443", "proxies: [{name: bad, type: unknown, server: host.example, port: 443}]"} {
		if _, _, err := parseSubscription([]byte(bad)); err == nil {
			t.Fatalf("invalid subscription accepted: %s", strings.SplitN(bad, ":", 2)[0])
		}
	}
}

func TestShadowsocksLegacyEncodingAndPlugin(t *testing.T) {
	raw := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:p:a@node.example:8388")) + "#SS"
	n, _, e := parseSubscription([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	if text(n[0], "password") != "p:a" {
		t.Fatal("legacy password changed")
	}
	p := Proxy{"type": "ss", "name": "SS plugin", "server": "node.example", "port": 443, "cipher": "aes-128-gcm", "password": "p", "plugin": "obfs", "plugin-opts": map[string]any{"mode": "http", "host": "edge.example"}}
	u, e := proxyURI(p)
	if e != nil {
		t.Fatal(e)
	}
	n, _, e = parseSubscription([]byte(u))
	if e != nil {
		t.Fatal(e)
	}
	if str(obj(n[0]["plugin-opts"])["mode"]) != "http" {
		t.Fatal("plugin parameters changed")
	}
}

func TestVMessYAMLTransportParametersAndLossyExport(t *testing.T) {
	p := Proxy{"name": "VMess h2", "type": "vmess", "server": "node.example", "port": 443, "uuid": testUUID, "alterId": 0, "cipher": "auto", "network": "h2", "tls": true, "servername": "edge.example", "h2-opts": map[string]any{"path": "/path", "host": []string{"edge.example"}}, "alpn": []string{"h2"}, "client-fingerprint": "chrome", "skip-cert-verify": true}
	raw, err := proxyURI(p)
	if err != nil {
		t.Fatal(err)
	}
	nodes, _, err := parseSubscription([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	n := nodes[0]
	if text(n, "client-fingerprint") != "chrome" || !truth(n["skip-cert-verify"]) || str(obj(n["h2-opts"])["path"]) != "/path" || strings.Join(list(n["alpn"]), ",") != "h2" {
		t.Fatal("VMess transport or TLS fields lost")
	}
	p["network"] = "ws"
	delete(p, "h2-opts")
	p["ws-opts"] = map[string]any{"path": "/", "headers": map[string]any{"Host": "edge.example", "X-Private": "value"}}
	if _, err := proxyURI(p); err == nil {
		t.Fatal("custom headers must not be silently discarded")
	}
	nodes, _, err = parseSubscription([]byte("tuic://test-token@node.example:443#v4"))
	if err != nil || text(nodes[0], "token") != "test-token" {
		t.Fatal("TUIC token form not preserved")
	}
}
