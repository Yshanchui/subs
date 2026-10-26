package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type App struct {
	store         *Store
	client        *http.Client
	updateMu      sync.Mutex
	publicURL     string
	secureCookie  bool
	sessionMu     sync.Mutex
	sessions      map[string]session
	loginAttempts map[string]attempts
	loginSlots    chan struct{}
}

func newApp(store *Store, client *http.Client) *App {
	return &App{store: store, client: client, sessions: map[string]session{}, loginAttempts: map[string]attempts{}, loginSlots: make(chan struct{}, 4)}
}

func (a *App) refreshSource(ctx context.Context, id string) error {
	s := a.store.snapshot()
	var source *Source
	for _, v := range s.Sources {
		if v.ID == id {
			v := v
			source = &v
			break
		}
	}
	if source == nil {
		return errors.New("订阅源不存在")
	}
	b, err := fetch(ctx, a.client, source.URL)
	var nodes []Proxy
	var warnings []string
	if err == nil {
		nodes, warnings, err = parseSubscription(b)
	}
	updateErr := a.store.mutate(func(s *State) error {
		for i := range s.Sources {
			v := &s.Sources[i]
			if v.ID == id {
				v.AttemptedAt = time.Now().UTC()
				if err != nil {
					v.Error = err.Error()
				} else {
					v.Cache = nodes
					v.Warnings = warnings
					v.UpdatedAt = v.AttemptedAt
					v.Error = ""
				}
				return nil
			}
		}
		return errors.New("订阅源不存在")
	})
	if updateErr != nil {
		return updateErr
	}
	return err
}

func (a *App) refreshRules(ctx context.Context) error {
	acl, err := downloadACL(ctx, a.client, aclTemplateURL)
	if e := a.store.mutate(func(s *State) error {
		s.RuleAttemptedAt = time.Now().UTC()
		if err != nil {
			s.RuleError = err.Error()
		} else {
			s.ACL = acl
			s.RuleError = ""
		}
		return nil
	}); e != nil {
		return e
	}
	return err
}

func (a *App) publish(id string) error {
	s := a.store.snapshot()
	var c Collection
	found := false
	for _, v := range s.Collections {
		if v.ID == id {
			c = v
			found = true
			break
		}
	}
	if !found {
		return errors.New("订阅集合不存在")
	}
	nodes, sources := aggregate(s, c)
	if len(nodes) == 0 {
		return a.publicationError(id, errors.New("尚无可用的本地节点。添加并更新订阅源后再生成；已有快照保留"))
	}
	if s.ACL == nil {
		return a.publicationError(id, errors.New("尚无 ACL 规则，请先更新规则；已有快照保留"))
	}
	gen := generationName()
	dir := filepath.Join(a.store.dir, "snapshots", id, gen)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return a.publicationError(id, errors.New("创建快照目录失败"))
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(dir)
		}
	}()
	p := &Publication{Generation: gen, BuiltAt: time.Now().UTC(), Artifacts: map[string]Artifact{}, Sources: sources, RuleUpdatedAt: s.ACL.UpdatedAt}
	if c.Publication != nil {
		p.Previous = c.Publication.Generation
	}
	for format, filename := range formatFiles {
		b, meta, err := renderArtifact(format, nodes, s.ACL)
		meta.UpdatedAt = p.BuiltAt
		if err != nil {
			meta.Error = err.Error()
			if c.Publication != nil {
				if old, ok := c.Publication.Artifacts[format]; ok && old.SHA256 != "" {
					data, e := os.ReadFile(filepath.Join(a.store.dir, "snapshots", id, c.Publication.Generation, filename))
					if e != nil {
						return a.publicationError(id, errors.New("读取上一版快照失败，未发布新版本"))
					}
					b = data
					meta = old
					meta.Error = err.Error() + "；继续提供上一版"
				}
			}
		}
		p.Artifacts[format] = meta
		if len(b) > 0 {
			if err := atomicWrite(filepath.Join(dir, filename), b); err != nil {
				return a.publicationError(id, errors.New("写入快照失败，未发布新版本"))
			}
		}
	}
	if err := a.store.mutate(func(next *State) error {
		for i := range next.Collections {
			if next.Collections[i].ID == id {
				next.Collections[i].Publication = p
				next.Collections[i].Error = ""
				return nil
			}
		}
		return errors.New("订阅集合不存在")
	}); err != nil {
		return err
	}
	committed = true
	// Readers open the file while holding the state read lock, so old open files remain valid.
	a.store.mu.Lock()
	if c.Publication != nil && c.Publication.Previous != "" {
		_ = os.RemoveAll(filepath.Join(a.store.dir, "snapshots", id, c.Publication.Previous))
	}
	a.store.mu.Unlock()
	return nil
}

func (a *App) publicationError(id string, cause error) error {
	if err := a.store.mutate(func(s *State) error {
		for i := range s.Collections {
			if s.Collections[i].ID == id {
				s.Collections[i].Error = cause.Error()
				return nil
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return cause
}

func (a *App) publishAll() []string {
	var failures []string
	for _, c := range a.store.snapshot().Collections {
		if c.Publication == nil {
			nodes, _ := aggregate(a.store.snapshot(), c)
			if len(nodes) == 0 {
				continue
			}
		}
		if err := a.publish(c.ID); err != nil {
			failures = append(failures, c.Name+"："+err.Error())
		} else {
			s := a.store.snapshot()
			i := collectionIndex(&s, c.ID)
			if i >= 0 && s.Collections[i].Publication != nil {
				for format, meta := range s.Collections[i].Publication.Artifacts {
					if meta.Error != "" {
						failures = append(failures, c.Name+" / "+format+"："+meta.Error)
					}
				}
			}
		}
	}
	return failures
}

func (a *App) runRefresh(ctx context.Context, sourceID string, rules bool) map[string]any {
	var failures []string
	updated := 0
	if rules {
		if err := a.refreshRules(ctx); err != nil {
			failures = append(failures, "ACL："+err.Error())
		} else {
			updated++
		}
	}
	var selected []Source
	for _, s := range a.store.snapshot().Sources {
		if (sourceID != "" && s.ID != sourceID) || (!s.Enabled && sourceID == "") {
			continue
		}
		selected = append(selected, s)
	}
	count, errs := a.refreshSources(ctx, selected)
	updated += count
	failures = append(failures, errs...)
	failures = append(failures, a.publishAll()...)
	return map[string]any{"updated": updated, "errors": failures}
}

func (a *App) refreshSources(ctx context.Context, sources []Source) (int, []string) {
	errs := make([]error, len(sources))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, s := range sources {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()
			errs[i] = a.refreshSource(ctx, id)
		}(i, s.ID)
	}
	wg.Wait()
	count := 0
	var failures []string
	for i, err := range errs {
		if err == nil {
			count++
		} else {
			failures = append(failures, sources[i].Name+"：更新失败，保留旧缓存")
		}
	}
	return count, failures
}

func (a *App) scheduler(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if a.updateMu.TryLock() {
			jobCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			s := a.store.snapshot()
			now := time.Now()
			ruleDue := s.RuleAttemptedAt.IsZero() || now.Sub(s.RuleAttemptedAt) >= time.Duration(s.Settings.RuleIntervalHours)*time.Hour
			changed := false
			if ruleDue {
				if a.refreshRules(jobCtx) == nil {
					changed = true
				}
			}
			var selected []Source
			for _, src := range s.Sources {
				due := s.Settings.SourceIntervalMinutes > 0 && (src.AttemptedAt.IsZero() || now.Sub(src.AttemptedAt) >= time.Duration(s.Settings.SourceIntervalMinutes)*time.Minute)
				if src.Enabled && due {
					selected = append(selected, src)
				}
			}
			count, _ := a.refreshSources(jobCtx, selected)
			if count > 0 {
				changed = true
			}
			if changed {
				a.publishAll()
			}
			cancel()
			a.updateMu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func sourceIndex(s *State, id string) int {
	for i := range s.Sources {
		if s.Sources[i].ID == id {
			return i
		}
	}
	return -1
}
func collectionIndex(s *State, id string) int {
	for i := range s.Collections {
		if s.Collections[i].ID == id {
			return i
		}
	}
	return -1
}
func checkName(name string) error {
	if name == "" || len([]rune(name)) > 80 || cleanName(name) != name {
		return fmt.Errorf("名称须为 1–80 个字符，且不含控制字符")
	}
	return nil
}
