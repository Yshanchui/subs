package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v3"
)

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func text(p Proxy, k string) string { return str(p[k]) }
func integer(v any) int             { n, _ := strconv.Atoi(str(v)); return n }
func truth(v any) bool              { s := str(v); return s == "true" || s == "1" }
func obj(v any) map[string]any      { m, _ := v.(map[string]any); return m }
func list(v any) []string {
	var r []string
	switch a := v.(type) {
	case []any:
		for _, v := range a {
			r = append(r, str(v))
		}
	case []string:
		r = a
	case string:
		if a != "" {
			r = strings.Split(a, ",")
		}
	}
	return r
}

func decode64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("Base64 无效")
}

func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	r := []rune(strings.TrimSpace(s))
	if len(r) > 160 {
		r = r[:160]
	}
	return string(r)
}

func parseSubscription(data []byte) ([]Proxy, []string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	var root map[string]any
	var nodes []Proxy
	if err := yaml.Unmarshal([]byte(s), &root); err == nil && root["proxies"] != nil {
		items, ok := root["proxies"].([]any)
		if !ok {
			return nil, nil, errors.New("YAML proxies 必须是节点数组")
		}
		for _, v := range items {
			m, ok := v.(map[string]any)
			if !ok {
				return nil, nil, errors.New("节点必须是对象")
			}
			for k := range m {
				if strings.HasPrefix(k, "__") {
					delete(m, k)
				}
			}
			nodes = append(nodes, Proxy(m))
		}
	} else {
		if !strings.Contains(s, "://") {
			b, err := decode64(s)
			if err != nil {
				return nil, nil, errors.New("内容既不是 Clash YAML，也不是 URI/Base64 订阅")
			}
			s = string(b)
		}
		for i, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			p, err := parseURI(line)
			if err != nil {
				return nil, nil, fmt.Errorf("第 %d 行：%s", i+1, err)
			}
			nodes = append(nodes, p)
		}
	}
	if len(nodes) == 0 || len(nodes) > 10000 {
		return nil, nil, errors.New("订阅必须包含 1–10000 个节点")
	}
	var result []Proxy
	metadata := 0
	for i, p := range nodes {
		if err := validateProxy(p); err != nil {
			return nil, nil, fmt.Errorf("第 %d 个节点：%s", i+1, err)
		}
		name := text(p, "name")
		placeholder := false
		for _, prefix := range []string{"Traffic:", "Expire:", "剩余流量：", "剩余流量:", "套餐到期：", "套餐到期:", "距离下次重置剩余："} {
			if strings.HasPrefix(name, prefix) {
				placeholder = true
				break
			}
		}
		if placeholder {
			metadata++
			continue
		}
		result = append(result, p)
	}
	if len(result) == 0 {
		return nil, nil, errors.New("订阅只有流量/到期信息占位项，没有可用节点")
	}
	var warnings []string
	if metadata > 0 {
		warnings = append(warnings, fmt.Sprintf("已排除 %d 个流量/到期信息占位项", metadata))
	}
	return result, warnings, nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validateProxy(p Proxy) error {
	t := strings.ToLower(text(p, "type"))
	if t == "hy2" {
		t = "hysteria2"
	}
	p["type"] = t
	if !strings.Contains("|ss|ssr|vmess|vless|trojan|hysteria|hysteria2|tuic|snell|socks5|http|wireguard|ssh|anytls|", "|"+t+"|") {
		return errors.New("不支持该节点协议，未覆盖旧缓存")
	}
	if text(p, "server") == "" || strings.ContainsAny(text(p, "server"), "\r\n\x00") {
		return errors.New("server 无效")
	}
	port := integer(p["port"])
	if port < 1 || port > 65535 {
		return errors.New("port 必须为 1–65535")
	}
	p["port"] = port
	if text(p, "name") == "" {
		p["name"] = t + "-" + text(p, "server")
	}
	p["name"] = cleanName(text(p, "name"))
	if t == "ss" || t == "ssr" {
		if text(p, "cipher") == "" || text(p, "password") == "" {
			return errors.New("Shadowsocks 缺少 cipher/password")
		}
	}
	if t == "vmess" || t == "vless" || (t == "tuic" && text(p, "token") == "") {
		if !uuidPattern.MatchString(text(p, "uuid")) {
			return errors.New("uuid 格式无效")
		}
	}
	if t == "trojan" || t == "hysteria2" || t == "anytls" {
		if text(p, "password") == "" {
			return errors.New("缺少 password")
		}
	}
	if t == "tuic" && text(p, "token") == "" && (text(p, "uuid") == "" || text(p, "password") == "") {
		return errors.New("TUIC 缺少 uuid/password")
	}
	return nil
}

func parseURI(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return nil, errors.New("节点链接无效")
	}
	t := strings.ToLower(u.Scheme)
	if t == "ssr" {
		return parseSSR(raw)
	}
	if t == "ss" {
		return parseSS(raw)
	}
	if t == "vmess" && !strings.Contains(strings.TrimPrefix(raw, "vmess://"), "@") {
		return parseVMess(raw)
	}
	if t == "hy2" {
		t = "hysteria2"
	}
	if t == "socks" {
		t = "socks5"
	}
	if !strings.Contains("|vmess|vless|trojan|hysteria2|tuic|socks5|http|https|", "|"+t+"|") {
		return nil, errors.New("不支持的 URI 协议")
	}
	port := integer(u.Port())
	if port == 0 {
		port = 443
	}
	p := Proxy{"name": u.Fragment, "type": t, "server": u.Hostname(), "port": port, "udp": true, "__uri": raw}
	q := u.Query()
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	switch t {
	case "vmess", "vless":
		p["uuid"] = user
		p["network"] = first(q.Get("type"), "tcp")
		if t == "vmess" {
			p["alterId"] = 0
			p["cipher"] = first(q.Get("encryption"), "auto")
		}
		if q.Get("flow") != "" {
			p["flow"] = q.Get("flow")
		}
	case "trojan", "hysteria2":
		p["password"] = user
		if pass != "" {
			p["password"] = user + ":" + pass
		}
		p["tls"] = true
	case "tuic":
		if pass == "" {
			p["token"] = user
		} else {
			p["uuid"] = user
			p["password"] = pass
		}
		p["congestion-controller"] = first(q.Get("congestion_control"), "bbr")
		if q.Get("udp_relay_mode") != "" {
			p["udp-relay-mode"] = q.Get("udp_relay_mode")
		}
	case "http", "https", "socks5":
		if user != "" {
			p["username"] = user
			p["password"] = pass
		}
		if t == "https" {
			p["type"] = "http"
			p["tls"] = true
		}
	}
	if q.Get("security") == "tls" || q.Get("security") == "reality" {
		p["tls"] = true
	}
	if truth(q.Get("allowInsecure")) || truth(q.Get("insecure")) {
		p["skip-cert-verify"] = true
	}
	if s := first(q.Get("sni"), q.Get("peer")); s != "" {
		if t == "vless" || t == "vmess" {
			p["servername"] = s
		} else {
			p["sni"] = s
		}
	}
	if a := q.Get("alpn"); a != "" {
		p["alpn"] = strings.Split(a, ",")
	}
	if a := q.Get("fp"); a != "" {
		p["client-fingerprint"] = a
	}
	if q.Get("security") == "reality" {
		if q.Get("pbk") == "" {
			return nil, errors.New("Reality 缺少 public key")
		}
		p["reality-opts"] = map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
	}
	switch text(p, "network") {
	case "ws":
		o := map[string]any{"path": first(q.Get("path"), "/")}
		if q.Get("host") != "" {
			o["headers"] = map[string]any{"Host": q.Get("host")}
		}
		p["ws-opts"] = o
	case "grpc":
		p["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
	case "h2":
		p["h2-opts"] = map[string]any{"path": first(q.Get("path"), "/"), "host": strings.Split(q.Get("host"), ",")}
	case "http":
		p["http-opts"] = map[string]any{"method": "GET", "path": []string{first(q.Get("path"), "/")}, "headers": map[string]any{"Host": strings.Split(q.Get("host"), ",")}}
	case "tcp", "":
	default:
		return nil, errors.New("URI 使用了暂不支持的传输层")
	}
	if t == "hysteria2" {
		if m := q.Get("mport"); m != "" {
			p["ports"] = m
		}
		if o := q.Get("obfs"); o != "" {
			p["obfs"] = o
			p["obfs-password"] = q.Get("obfs-password")
		}
		if pin := q.Get("pinSHA256"); pin != "" {
			p["fingerprint"] = pin
		}
	}
	return p, nil
}

func first(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func parseSS(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("SS 链接无效")
	}
	if !strings.Contains(u.Host, "@") && u.User == nil {
		payload := strings.TrimPrefix(strings.SplitN(strings.SplitN(raw, "#", 2)[0], "?", 2)[0], "ss://")
		b, e := decode64(payload)
		if e != nil {
			return nil, errors.New("SS 凭据编码无效")
		}
		v, e := url.Parse("ss://" + string(b))
		if e != nil {
			return nil, errors.New("SS 链接无效")
		}
		v.Fragment = u.Fragment
		v.RawQuery = u.RawQuery
		u = v
	}
	if u.User == nil {
		return nil, errors.New("SS 缺少凭据")
	}
	cipher := u.User.Username()
	password, has := u.User.Password()
	if !has {
		b, e := decode64(cipher)
		if e != nil {
			return nil, errors.New("SS 凭据编码无效")
		}
		parts := strings.SplitN(string(b), ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("SS 凭据无效")
		}
		cipher, password = parts[0], parts[1]
	}
	p := Proxy{"name": u.Fragment, "type": "ss", "server": u.Hostname(), "port": integer(u.Port()), "cipher": cipher, "password": password, "udp": true, "__uri": raw}
	if plugin := u.Query().Get("plugin"); plugin != "" {
		parts := strings.Split(plugin, ";")
		name := parts[0]
		if name == "simple-obfs" || name == "obfs-local" {
			name = "obfs"
		}
		p["plugin"] = name
		o := map[string]any{}
		for _, part := range parts[1:] {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				key := kv[0]
				if key == "obfs" {
					key = "mode"
				}
				if key == "obfs-host" {
					key = "host"
				}
				o[key] = kv[1]
			} else {
				o[kv[0]] = true
			}
		}
		p["plugin-opts"] = o
	}
	return p, nil
}

func parseSSR(raw string) (Proxy, error) {
	b, e := decode64(strings.TrimPrefix(raw, "ssr://"))
	if e != nil {
		return nil, errors.New("SSR 编码无效")
	}
	parts := strings.SplitN(string(b), "/?", 2)
	fields := strings.Split(parts[0], ":")
	if len(fields) < 6 {
		return nil, errors.New("SSR 字段不足")
	}
	n := len(fields)
	pw, e := decode64(fields[n-1])
	if e != nil {
		return nil, errors.New("SSR 密码编码无效")
	}
	p := Proxy{"type": "ssr", "server": strings.Join(fields[:n-5], ":"), "port": integer(fields[n-5]), "protocol": fields[n-4], "cipher": fields[n-3], "obfs": fields[n-2], "password": string(pw), "__uri": raw}
	if len(parts) == 2 {
		q, _ := url.ParseQuery(parts[1])
		for k, target := range map[string]string{"remarks": "name", "protoparam": "protocol-param", "obfsparam": "obfs-param"} {
			if q.Get(k) != "" {
				v, err := decode64(q.Get(k))
				if err != nil {
					return nil, errors.New("SSR 参数编码无效")
				}
				p[target] = string(v)
			}
		}
	}
	return p, nil
}

func parseVMess(raw string) (Proxy, error) {
	b, e := decode64(strings.TrimPrefix(raw, "vmess://"))
	if e != nil {
		return nil, errors.New("VMess 编码无效")
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return nil, errors.New("VMess JSON 无效")
	}
	p := Proxy{"name": str(v["ps"]), "type": "vmess", "server": str(v["add"]), "port": integer(v["port"]), "uuid": str(v["id"]), "alterId": integer(v["aid"]), "cipher": first(str(v["scy"]), "auto"), "network": first(str(v["net"]), "tcp"), "udp": true, "__uri": raw}
	if str(v["tls"]) == "tls" {
		p["tls"] = true
		p["servername"] = first(str(v["sni"]), str(v["host"]))
	}
	if str(v["fp"]) != "" {
		p["client-fingerprint"] = str(v["fp"])
	}
	if truth(v["allowInsecure"]) {
		p["skip-cert-verify"] = true
	}
	if str(v["alpn"]) != "" {
		p["alpn"] = strings.Split(str(v["alpn"]), ",")
	}
	switch text(p, "network") {
	case "ws":
		p["ws-opts"] = map[string]any{"path": first(str(v["path"]), "/"), "headers": map[string]any{"Host": str(v["host"])}}
	case "grpc":
		p["grpc-opts"] = map[string]any{"grpc-service-name": str(v["path"])}
	case "tcp":
		if str(v["type"]) != "" && str(v["type"]) != "none" {
			return nil, errors.New("暂不支持 VMess TCP 伪装，已保留旧缓存")
		}
	case "h2":
		p["h2-opts"] = map[string]any{"path": first(str(v["path"]), "/"), "host": strings.Split(str(v["host"]), ",")}
	case "http":
		p["http-opts"] = map[string]any{"method": "GET", "path": []string{first(str(v["path"]), "/")}, "headers": map[string]any{"Host": strings.Split(str(v["host"]), ",")}}
	default:
		return nil, errors.New("VMess 传输层暂不支持")
	}
	return p, nil
}

func proxyURI(p Proxy) (string, error) {
	if raw := text(p, "__uri"); raw != "" {
		u, e := url.Parse(raw)
		if e == nil && u.Scheme != "vmess" && u.Scheme != "ssr" {
			u.Fragment = text(p, "name")
			return u.String(), nil
		}
	}
	if err := checkURIOptions(p); err != nil {
		return "", err
	}
	t := text(p, "type")
	host := net.JoinHostPort(text(p, "server"), text(p, "port"))
	name := text(p, "name")
	u := &url.URL{Scheme: t, Host: host, Fragment: name}
	q := url.Values{}
	switch t {
	case "ss":
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(text(p, "cipher") + ":" + text(p, "password"))))
		if plugin := text(p, "plugin"); plugin != "" {
			if plugin == "obfs" {
				plugin = "obfs-local"
			}
			parts := []string{plugin}
			o := obj(p["plugin-opts"])
			for _, k := range []string{"mode", "host", "path", "tls", "mux"} {
				v := o[k]
				if v == nil {
					continue
				}
				key := k
				if k == "mode" && plugin == "obfs-local" {
					key = "obfs"
				}
				if k == "host" && plugin == "obfs-local" {
					key = "obfs-host"
				}
				if truth(v) {
					parts = append(parts, key)
				} else {
					parts = append(parts, key+"="+str(v))
				}
			}
			q.Set("plugin", strings.Join(parts, ";"))
		}
	case "ssr":
		params := url.Values{}
		params.Set("remarks", base64.RawURLEncoding.EncodeToString([]byte(name)))
		for k, target := range map[string]string{"protocol-param": "protoparam", "obfs-param": "obfsparam"} {
			if text(p, k) != "" {
				params.Set(target, base64.RawURLEncoding.EncodeToString([]byte(text(p, k))))
			}
		}
		payload := strings.Join([]string{text(p, "server"), text(p, "port"), first(text(p, "protocol"), "origin"), text(p, "cipher"), first(text(p, "obfs"), "plain"), base64.RawURLEncoding.EncodeToString([]byte(text(p, "password")))}, ":") + "/?" + params.Encode()
		return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(payload)), nil
	case "vmess":
		v := map[string]any{"v": "2", "ps": name, "add": text(p, "server"), "port": text(p, "port"), "id": text(p, "uuid"), "aid": text(p, "alterId"), "scy": first(text(p, "cipher"), "auto"), "net": first(text(p, "network"), "tcp"), "type": "none"}
		if truth(p["tls"]) {
			v["tls"] = "tls"
			v["sni"] = text(p, "servername")
		}
		if truth(p["skip-cert-verify"]) {
			v["allowInsecure"] = true
		}
		if a := list(p["alpn"]); len(a) > 0 {
			v["alpn"] = strings.Join(a, ",")
		}
		if text(p, "client-fingerprint") != "" {
			v["fp"] = text(p, "client-fingerprint")
		}
		if o := obj(p["ws-opts"]); o != nil {
			v["path"] = str(o["path"])
			v["host"] = str(obj(o["headers"])["Host"])
		}
		if o := obj(p["grpc-opts"]); o != nil {
			v["path"] = str(o["grpc-service-name"])
		}
		if o := obj(p["h2-opts"]); o != nil {
			v["path"] = str(o["path"])
			v["host"] = strings.Join(list(o["host"]), ",")
		}
		if o := obj(p["http-opts"]); o != nil {
			paths := list(o["path"])
			if len(paths) > 1 {
				return "", errors.New("多路径 HTTP 传输不能无损导出")
			}
			if len(paths) == 1 {
				v["path"] = paths[0]
			}
			v["host"] = strings.Join(list(obj(o["headers"])["Host"]), ",")
			if method := str(o["method"]); method != "" && method != "GET" {
				return "", errors.New("非 GET HTTP 传输不能无损导出")
			}
		}
		if p["reality-opts"] != nil {
			return "", errors.New("VMess Reality 无通用导出")
		}
		b, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
	case "vless":
		u.User = url.User(text(p, "uuid"))
		q.Set("encryption", "none")
		if text(p, "flow") != "" {
			q.Set("flow", text(p, "flow"))
		}
	case "trojan", "hysteria2":
		u.User = url.User(text(p, "password"))
		if t == "hysteria2" {
			for key, target := range map[string]string{"obfs": "obfs", "obfs-password": "obfs-password", "ports": "mport", "fingerprint": "pinSHA256"} {
				if text(p, key) != "" {
					q.Set(target, text(p, key))
				}
			}
		}
	case "tuic":
		if text(p, "token") != "" {
			u.User = url.User(text(p, "token"))
		} else {
			u.User = url.UserPassword(text(p, "uuid"), text(p, "password"))
		}
		q.Set("congestion_control", first(text(p, "congestion-controller"), "bbr"))
		if text(p, "udp-relay-mode") != "" {
			q.Set("udp_relay_mode", text(p, "udp-relay-mode"))
		}
	case "socks5", "http":
		if text(p, "username") != "" {
			u.User = url.UserPassword(text(p, "username"), text(p, "password"))
		}
		if t == "http" && truth(p["tls"]) {
			u.Scheme = "https"
		}
	default:
		return "", errors.New("该协议没有受支持的 Shadowrocket URI 导出")
	}
	if truth(p["tls"]) {
		q.Set("security", "tls")
	}
	if r := obj(p["reality-opts"]); r != nil {
		q.Set("security", "reality")
		q.Set("pbk", str(r["public-key"]))
		q.Set("sid", str(r["short-id"]))
	}
	if s := first(text(p, "servername"), text(p, "sni")); s != "" {
		q.Set("sni", s)
	}
	if truth(p["skip-cert-verify"]) {
		q.Set("allowInsecure", "1")
		q.Set("insecure", "1")
	}
	if a := list(p["alpn"]); len(a) > 0 {
		q.Set("alpn", strings.Join(a, ","))
	}
	if text(p, "client-fingerprint") != "" {
		q.Set("fp", text(p, "client-fingerprint"))
	}
	if n := text(p, "network"); n != "" {
		q.Set("type", n)
	}
	if o := obj(p["ws-opts"]); o != nil {
		q.Set("path", str(o["path"]))
		if h := obj(o["headers"]); h != nil {
			q.Set("host", str(h["Host"]))
		}
	}
	if o := obj(p["grpc-opts"]); o != nil {
		q.Set("serviceName", str(o["grpc-service-name"]))
	}
	if o := obj(p["h2-opts"]); o != nil {
		q.Set("path", str(o["path"]))
		q.Set("host", strings.Join(list(o["host"]), ","))
	}
	if o := obj(p["http-opts"]); o != nil {
		paths := list(o["path"])
		if len(paths) > 1 {
			return "", errors.New("多路径 HTTP 传输不能无损导出")
		}
		if len(paths) == 1 {
			q.Set("path", paths[0])
		}
		q.Set("host", strings.Join(list(obj(o["headers"])["Host"]), ","))
		if method := str(o["method"]); method != "" && method != "GET" {
			return "", errors.New("非 GET HTTP 传输不能无损导出")
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func checkURIOptions(p Proxy) error {
	allowed := "|name|type|server|port|password|uuid|udp|tls|servername|sni|skip-cert-verify|client-fingerprint|alpn|network|reality-opts|flow|ws-opts|grpc-opts|h2-opts|http-opts|alterId|cipher|plugin|plugin-opts|protocol|protocol-param|obfs|obfs-param|obfs-password|ports|mport|fingerprint|token|congestion-controller|udp-relay-mode|username|"
	for k := range p {
		if !strings.HasPrefix(k, "__") && !strings.Contains(allowed, "|"+k+"|") {
			return errors.New("包含 URI 无法表达的节点选项")
		}
	}
	for field, keys := range map[string]string{"ws-opts": "|path|headers|", "grpc-opts": "|grpc-service-name|", "h2-opts": "|path|host|", "http-opts": "|method|path|headers|", "reality-opts": "|public-key|short-id|"} {
		o := obj(p[field])
		for k := range o {
			if !strings.Contains(keys, "|"+k+"|") {
				return errors.New("包含 URI 无法表达的传输选项")
			}
		}
		if field == "ws-opts" || field == "http-opts" {
			for k := range obj(o["headers"]) {
				if !strings.EqualFold(k, "Host") {
					return errors.New("自定义传输请求头无法无损导出")
				}
			}
		}
	}
	if plugin := text(p, "plugin"); plugin != "" {
		keys := ""
		switch plugin {
		case "obfs":
			keys = "|mode|host|"
		case "v2ray-plugin":
			keys = "|mode|host|path|tls|mux|"
		default:
			return errors.New("该 SS 插件没有通用 URI 导出")
		}
		for k := range obj(p["plugin-opts"]) {
			if !strings.Contains(keys, "|"+k+"|") {
				return errors.New("SS 插件参数无法无损导出")
			}
		}
	}
	return nil
}
