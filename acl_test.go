package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const fixtureTemplate = "[custom]\ncustom_proxy_group=Proxy`select`[]Auto`.*\ncustom_proxy_group=Auto`url-test`.*`http://www.gstatic.com/generate_204`300,,50\ncustom_proxy_group=Local`select`[]DIRECT`[]Proxy\ncustom_proxy_group=Korea`url-test`(韩国|KR)`http://www.gstatic.com/generate_204`300,,50\nruleset=Local,https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Local.list\nruleset=Proxy,[]FINAL\n"

func fixtureACL() *ACL {
	return &ACL{Groups: []Group{{Name: "Proxy", Type: "select", Options: []string{"[]Auto", ".*"}}, {Name: "Auto", Type: "url-test", Options: []string{".*"}, URL: "http://www.gstatic.com/generate_204", Interval: 300, Tolerance: 50}, {Name: "Local", Type: "select", Options: []string{"[]DIRECT", "[]Proxy"}}, {Name: "Korea", Type: "url-test", Options: []string{"韩国|KR"}, URL: "http://www.gstatic.com/generate_204", Interval: 300}}, Rules: []Rule{{Kind: "DOMAIN-SUFFIX", Value: "cn", Policy: "Local"}, {Kind: "IP-CIDR", Value: "10.0.0.0/8", Policy: "Local", NoResolve: true}, {Kind: "USER-AGENT", Value: "Test*", Policy: "Proxy"}, {Kind: "PROCESS-NAME", Value: "test.exe", Policy: "Proxy"}, {Kind: "MATCH", Policy: "Proxy"}}, UpdatedAt: time.Now().UTC(), Lists: 1}
}

func TestACLDownloadAndFailClosed(t *testing.T) {
	fail := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := fixtureTemplate
		status := 200
		if strings.HasSuffix(r.URL.Path, ".list") {
			body = "# comment\nDOMAIN-SUFFIX,cn\nIP-CIDR,10.0.0.0/8,no-resolve"
			if fail {
				status = 500
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	a, err := downloadACL(context.Background(), client, aclTemplateURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Rules) != 3 || len(a.Groups) != 4 || a.Rules[1].Policy != "Local" || !a.Rules[1].NoResolve {
		t.Fatal("template mapping or rule order lost")
	}
	fail = true
	if _, err := downloadACL(context.Background(), client, aclTemplateURL); err == nil {
		t.Fatal("failed list must invalidate complete new rules version")
	}
	for _, bad := range []string{strings.Replace(fixtureTemplate, "[]Auto", "[]Missing", 1), strings.Replace(fixtureTemplate, "custom_proxy_group=Auto`url-test`.*`http://www.gstatic.com/generate_204`300,,50", "custom_proxy_group=Auto`select`[]Proxy", 1)} {
		if _, _, err := parseTemplate([]byte(bad)); err == nil {
			t.Fatal("invalid group references/cycle accepted")
		}
	}
	r, err := parseRule("URL-REGEX,^https://example\\.com/(a,b){1,3}", "Proxy")
	if err != nil || r.Value != "^https://example\\.com/(a,b){1,3}" {
		t.Fatal("regex commas must be preserved")
	}
}

func TestAggregateNamesAndRegionMatching(t *testing.T) {
	s := State{ACL: fixtureACL(), Sources: []Source{{ID: "s", Name: "韩国机场", Enabled: true, Cache: []Proxy{{"name": "日本", "type": "trojan", "server": "a.example", "port": 443, "password": "test"}, {"name": "日本", "type": "trojan", "server": "b.example", "port": 443, "password": "test"}, {"name": "日本 (2)", "type": "trojan", "server": "c.example", "port": 443, "password": "test"}}}}}
	nodes, _ := aggregate(s, Collection{AllSources: true})
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[text(n, "name")] {
			t.Fatal("aggregate contains duplicate names")
		}
		seen[text(n, "name")] = true
	}
	groups := makeGroups(s.ACL.Groups, nodes)
	last := groups[len(groups)-1]
	if last["type"] != "select" {
		t.Fatal("region regex must match node name, not provider prefix")
	}
}

func TestClientExports(t *testing.T) {
	nodes := []Proxy{{"name": "香港 Trojan", "type": "trojan", "server": "node.example", "port": 443, "password": "test", "client-fingerprint": "chrome", "__uri": "trojan://test@node.example:443#old"}, {"name": "VLESS", "type": "vless", "server": "v.example", "port": 443, "uuid": testUUID}, {"name": "HY2", "type": "hysteria2", "server": "h.example", "port": 443, "password": "test"}}
	for _, format := range []string{"mihomo", "clash"} {
		b, meta, err := renderArtifact(format, nodes, fixtureACL())
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		if yaml.Unmarshal(b, &config) != nil {
			t.Fatal("invalid YAML")
		}
		if strings.Contains(string(b), "__uri") || strings.Contains(string(b), "include-all") || strings.Contains(string(b), "RULE-SET") {
			t.Fatal("output must be self contained")
		}
		if meta.ExcludedRules != 1 || meta.Rules != 4 {
			t.Fatal("unsupported rules must be counted")
		}
		if format == "clash" && (meta.Nodes != 1 || meta.ExcludedNodes != 2 || strings.Contains(string(b), "client-fingerprint")) {
			t.Fatal("legacy output leaked modern protocols/fields")
		}
		if format == "mihomo" && meta.Nodes != 3 {
			t.Fatal("Mihomo protocols missing")
		}
		if format == "mihomo" {
			dns, sniffer := obj(config["dns"]), obj(config["sniffer"])
			if config["ipv6"] != false || dns["enable"] != true || dns["ipv6"] != false || dns["enhanced-mode"] != "fake-ip" || dns["listen"] != "127.0.0.1:7874" {
				t.Fatal("Mihomo export must provide local Fake-IP DNS with IPv6 disabled")
			}
			if len(list(dns["default-nameserver"])) == 0 || len(list(dns["nameserver"])) == 0 || len(list(dns["proxy-server-nameserver"])) == 0 || dns["respect-rules"] != true {
				t.Fatal("rule-following DNS needs independent bootstrap and node-name resolvers")
			}
			if sniffer["enable"] != true || sniffer["force-dns-mapping"] != true || sniffer["parse-pure-ip"] != false || obj(sniffer["sniff"])["HTTP"] == nil || obj(sniffer["sniff"])["TLS"] == nil {
				t.Fatal("Mihomo export must enable HTTP/TLS sniffing without forcing pure-IP traffic")
			}
			if config["tun"] != nil || integer(config["mixed-port"]) != 7890 {
				t.Fatal("network defaults must retain the proxy port and leave TUN to the client")
			}
			if got := strings.Join(list(config["rules"]), "\n"); got != "DOMAIN-SUFFIX,cn,Local\nIP-CIDR,10.0.0.0/8,Local,no-resolve\nPROCESS-NAME,test.exe,Proxy\nMATCH,Proxy" {
				t.Fatal("network defaults changed ACL rule order or actions")
			}
		} else if config["dns"] != nil || config["sniffer"] != nil || config["ipv6"] != nil {
			t.Fatal("Mihomo network settings leaked into legacy Clash export")
		}
		groups := config["proxy-groups"].([]any)
		k := groups[len(groups)-1].(map[string]any)
		if k["type"] != "select" || k["proxies"].([]any)[0] != "REJECT" {
			t.Fatal("empty region must not silently direct traffic")
		}
	}
	b, meta, err := renderArtifact("shadowrocket-rules", nodes, fixtureACL())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "FINAL,PROXY") || !strings.Contains(string(b), "DOMAIN-SUFFIX,cn,DIRECT") || meta.ExcludedRules != 1 {
		t.Fatal("Shadowrocket rule actions incorrect")
	}
	b, meta, err = renderArtifact("shadowrocket", nodes, fixtureACL())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := parseSubscription(b)
	if err != nil || len(parsed) != 3 || meta.Nodes != 3 {
		t.Fatal("Shadowrocket subscription must round trip")
	}
}

func TestMihomoCoreAcceptsGeneratedConfig(t *testing.T) {
	binary := os.Getenv("SUBS_TEST_MIHOMO_BINARY")
	if binary == "" {
		t.Skip("set SUBS_TEST_MIHOMO_BINARY to validate with a real Mihomo core")
	}
	nodes := []Proxy{{"name": "Test Trojan", "type": "trojan", "server": "node.example", "port": 443, "password": "test-only-password", "udp": true}}
	b, _, err := renderArtifact("mihomo", nodes, fixtureACL())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, binary, "-t", "-d", dir, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("Mihomo rejected generated configuration: %v\n%s", err, out)
	}
}
