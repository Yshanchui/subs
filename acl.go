package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const aclTemplateURL = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full.ini"

type Group struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Options   []string `json:"options"`
	URL       string   `json:"url,omitempty"`
	Interval  int      `json:"interval,omitempty"`
	Tolerance int      `json:"tolerance,omitempty"`
}
type Rule struct {
	Kind      string `json:"kind"`
	Value     string `json:"value,omitempty"`
	Policy    string `json:"policy"`
	NoResolve bool   `json:"noResolve,omitempty"`
}
type ACL struct {
	Groups    []Group   `json:"groups"`
	Rules     []Rule    `json:"rules"`
	UpdatedAt time.Time `json:"updatedAt"`
	Lists     int       `json:"lists"`
}
type ruleset struct{ policy, url string }

func parseTemplate(data []byte) ([]Group, []ruleset, error) {
	var groups []Group
	var sets []ruleset
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if raw, ok := strings.CutPrefix(line, "custom_proxy_group="); ok {
			p := strings.Split(raw, "`")
			if len(p) < 3 || p[0] == "" || seen[p[0]] {
				return nil, nil, errors.New("ACL 策略组格式无效或重名")
			}
			seen[p[0]] = true
			g := Group{Name: p[0], Type: p[1], Options: p[2:]}
			if g.Type == "url-test" || g.Type == "fallback" || g.Type == "load-balance" {
				if len(p) < 5 {
					return nil, nil, errors.New("ACL 测速组参数不完整")
				}
				g.Options = p[2 : len(p)-2]
				g.URL = p[len(p)-2]
				timing := strings.Split(p[len(p)-1], ",")
				g.Interval = integer(timing[0])
				if g.Interval < 30 {
					g.Interval = 300
				}
				if len(timing) > 2 {
					g.Tolerance = integer(timing[2])
				}
				if validateURL(g.URL) != nil {
					return nil, nil, errors.New("ACL 测速 URL 无效")
				}
			} else if g.Type != "select" {
				return nil, nil, errors.New("ACL 出现不支持的策略组类型")
			}
			for _, o := range g.Options {
				if !strings.HasPrefix(o, "[]") {
					if _, err := regexp.Compile(o); err != nil {
						return nil, nil, errors.New("ACL 节点筛选正则不兼容")
					}
				}
			}
			groups = append(groups, g)
		}
		if raw, ok := strings.CutPrefix(line, "ruleset="); ok {
			p := strings.SplitN(raw, ",", 2)
			if len(p) != 2 || p[0] == "" {
				return nil, nil, errors.New("ACL ruleset 格式无效")
			}
			sets = append(sets, ruleset{p[0], p[1]})
		}
	}
	if len(groups) == 0 || len(sets) == 0 || len(sets) > 128 {
		return nil, nil, errors.New("ACL 模板为空或规则集数量异常")
	}
	for _, s := range sets {
		if !seen[s.policy] && s.policy != "DIRECT" && s.policy != "REJECT" {
			return nil, nil, errors.New("ACL 规则引用不存在的策略组")
		}
	}
	for _, g := range groups {
		for _, o := range g.Options {
			if strings.HasPrefix(o, "[]") {
				ref := strings.TrimPrefix(o, "[]")
				if ref != "DIRECT" && ref != "REJECT" && !seen[ref] {
					return nil, nil, errors.New("ACL 策略组引用不存在")
				}
			}
		}
	}
	// Reject cycles before they can become invalid client configurations.
	visiting, done := map[string]bool{}, map[string]bool{}
	gm := map[string]Group{}
	for _, g := range groups {
		gm[g.Name] = g
	}
	var visit func(string) bool
	visit = func(n string) bool {
		if done[n] {
			return true
		}
		if visiting[n] {
			return false
		}
		visiting[n] = true
		for _, o := range gm[n].Options {
			if strings.HasPrefix(o, "[]") {
				ref := strings.TrimPrefix(o, "[]")
				if _, ok := gm[ref]; ok && !visit(ref) {
					return false
				}
			}
		}
		visiting[n] = false
		done[n] = true
		return true
	}
	for n := range gm {
		if !visit(n) {
			return nil, nil, errors.New("ACL 策略组存在循环引用")
		}
	}
	return groups, sets, nil
}

func parseRule(line, policy string) (Rule, error) {
	line = strings.TrimSpace(line)
	kind, value, hasValue := strings.Cut(line, ",")
	if strings.ToUpper(kind) == "URL-REGEX" || strings.ToUpper(kind) == "USER-AGENT" || strings.ToUpper(kind) == "DOMAIN-REGEX" {
		if !hasValue || value == "" {
			return Rule{}, errors.New("ACL 正则或 User-Agent 规则缺少参数")
		}
		return Rule{Kind: strings.ToUpper(kind), Value: value, Policy: policy}, nil
	}
	p := strings.Split(line, ",")
	r := Rule{Policy: policy, Kind: strings.ToUpper(strings.TrimSpace(p[0]))}
	if r.Kind == "FINAL" || r.Kind == "MATCH" {
		r.Kind = "MATCH"
		if len(p) != 1 {
			return r, errors.New("FINAL 语法无效")
		}
		return r, nil
	}
	if !strings.Contains("|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|DOMAIN-REGEX|IP-CIDR|IP-CIDR6|SRC-IP-CIDR|GEOIP|IP-ASN|PROCESS-NAME|PROCESS-PATH|USER-AGENT|URL-REGEX|DST-PORT|SRC-PORT|NETWORK|", "|"+r.Kind+"|") {
		return r, errors.New("ACL 出现未知规则类型")
	}
	if len(p) < 2 || len(p) > 3 || strings.TrimSpace(p[1]) == "" {
		return r, errors.New("ACL 规则参数无效")
	}
	r.Value = strings.TrimSpace(p[1])
	if len(p) == 3 {
		if strings.TrimSpace(p[2]) != "no-resolve" {
			return r, errors.New("ACL 规则包含不支持的参数")
		}
		r.NoResolve = true
	}
	return r, nil
}

func downloadACL(ctx context.Context, client *http.Client, templateURL string) (*ACL, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	b, err := fetch(ctx, client, templateURL)
	if err != nil {
		return nil, err
	}
	groups, sets, err := parseTemplate(b)
	if err != nil {
		return nil, err
	}
	contents := make([][]byte, len(sets))
	errs := make([]error, len(sets))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, s := range sets {
		if strings.HasPrefix(s.url, "[]") {
			contents[i] = []byte(strings.TrimPrefix(s.url, "[]"))
			continue
		}
		u, e := url.Parse(s.url)
		if e != nil || u.Scheme != "https" || u.Host != "raw.githubusercontent.com" || !strings.HasPrefix(u.Path, "/ACL4SSR/ACL4SSR/") || u.RawQuery != "" {
			return nil, errors.New("ACL 模板引用了官方仓库以外的规则地址")
		}
		wg.Add(1)
		go func(i int, raw string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()
			contents[i], errs[i] = fetch(ctx, client, raw)
		}(i, s.url)
	}
	wg.Wait()
	acl := &ACL{Groups: groups, UpdatedAt: time.Now().UTC()}
	seen := map[string]bool{}
	for i, s := range sets {
		if errs[i] != nil {
			return nil, fmt.Errorf("ACL 第 %d 个规则集下载失败；保留旧版本", i+1)
		}
		if !strings.HasPrefix(s.url, "[]") {
			acl.Lists++
		}
		count := 0
		for n, line := range strings.Split(string(contents[i]), "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
				continue
			}
			r, err := parseRule(line, s.policy)
			if err != nil {
				return nil, fmt.Errorf("ACL 规则集 %d 第 %d 行：%s", i+1, n+1, err)
			}
			count++
			key := r.Kind + "," + r.Value + "," + r.Policy + fmt.Sprint(r.NoResolve)
			if !seen[key] {
				acl.Rules = append(acl.Rules, r)
				seen[key] = true
			}
			if len(acl.Rules) > 150000 {
				return nil, errors.New("ACL 规则数量超限")
			}
		}
		if count == 0 {
			return nil, errors.New("ACL 返回空规则集，保留旧版本")
		}
	}
	if len(acl.Rules) < 2 || acl.Rules[len(acl.Rules)-1].Kind != "MATCH" {
		return nil, errors.New("ACL 缺少末尾 FINAL 规则")
	}
	for i, r := range acl.Rules {
		if r.Kind == "MATCH" && i != len(acl.Rules)-1 {
			return nil, errors.New("ACL 包含提前终止的 FINAL 规则")
		}
	}
	return acl, nil
}
