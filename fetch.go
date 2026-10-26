package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var errPrivateUpstream = errors.New("上游 DNS 指向本地、私有或代理 Fake-IP 地址，请在可信内网/Fake-IP 环境中开启 SUBS_ALLOW_PRIVATE_UPSTREAM")

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return errors.New("地址必须是完整 HTTP(S) URL，且不含用户名、密码或片段")
	}
	if len(raw) > 8192 {
		return errors.New("订阅地址过长")
	}
	return nil
}

var reservedNetworks = func() []netip.Prefix {
	var networks []netip.Prefix
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "3fff::/20"} {
		networks = append(networks, netip.MustParsePrefix(cidr))
	}
	return networks
}()

func privateIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, network := range reservedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func newHTTPClient(allowPrivate bool) *http.Client {
	transport := &http.Transport{MaxIdleConns: 12, MaxIdleConnsPerHost: 4, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("上游地址无效")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("上游 DNS 解析失败")
		}
		if len(ips) == 0 {
			return nil, errors.New("上游 DNS 没有返回地址")
		}
		for _, ip := range ips {
			if !allowPrivate && privateIP(ip) {
				return nil, errPrivateUpstream
			}
		}
		var last error
		for _, ip := range ips {
			conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		_ = last
		return nil, errors.New("连接上游失败")
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("上游重定向次数过多")
		}
		return validateURL(req.URL.String())
	}}
}

func fetch(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	if err := validateURL(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, errors.New("上游地址无效")
	}
	req.Header.Set("User-Agent", "clash-verge/v2.0 Subs/1.0")
	req.Header.Set("Accept", "text/plain, application/yaml, */*")
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errPrivateUpstream) {
			return nil, errPrivateUpstream
		}
		if ctx.Err() != nil {
			return nil, errors.New("更新已取消")
		}
		return nil, errors.New("拉取失败：请检查上游开关、网络、DNS 或 TLS；保留旧快照")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("上游返回 HTTP %d；保留旧快照", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024+1))
	if err != nil {
		return nil, errors.New("读取上游失败")
	}
	if len(b) > 10*1024*1024 {
		return nil, errors.New("上游内容超过 10 MiB")
	}
	if strings.TrimSpace(string(b)) == "" {
		return nil, errors.New("上游返回空内容")
	}
	return b, nil
}
