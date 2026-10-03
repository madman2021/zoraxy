package h2cproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"imuslab.com/zoraxy/mod/access"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(Options{
		ConfigStore: t.TempDir(),
		AccessController: &access.Controller{
			DefaultAccessRule: &access.AccessRule{ID: "default"},
			ProxyAccessRule:   &sync.Map{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func saveTestRule(t *testing.T, m *Manager, domain, target string) Config {
	t.Helper()
	c, err := m.Save(Config{Domain: domain, Target: target, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigurationLifecycle(t *testing.T) {
	m := testManager(t)
	c := saveTestRule(t, m, "GRPC.Example.com.", "http://collector:4317/")
	if c.Domain != "grpc.example.com" || c.Target != "collector:4317" {
		t.Fatalf("normalization: %+v", c)
	}
	if _, err := m.Save(Config{Domain: "grpc.example.com", Target: "other:4317"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	bad := c
	bad.Target = "https://collector:4317"
	if _, err := m.Save(bad); err == nil {
		t.Fatal("TLS target accepted")
	}
	if got := m.List(); len(got) != 1 || got[0] != c {
		t.Fatalf("invalid edit changed config: %+v", got)
	}
	if err := m.SetEnabled(c.ID, false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://grpc.example.com/service/method", nil)
	r.Host = "GRPC.EXAMPLE.COM:443"
	if !m.Matches(r) {
		t.Fatal("stopped domain reservation lost")
	}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("stopped status = %d", w.Code)
	}
	m.Close()
	restored, err := NewManager(m.options)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got := restored.List(); len(got) != 1 || got[0].Enabled || got[0].ID != c.ID {
		t.Fatalf("restored = %+v", got)
	}
	if err := restored.SetEnabled(c.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := restored.Delete(c.ID); err != nil {
		t.Fatal(err)
	}
	if restored.OwnsDomain(c.Domain) {
		t.Fatal("deleted domain still reserved")
	}
	last, err := NewManager(m.options)
	if err != nil {
		t.Fatal(err)
	}
	defer last.Close()
	if len(last.List()) != 0 {
		t.Fatal("deletion was not persisted")
	}
}

func TestPersistenceFailureKeepsService(t *testing.T) {
	m := testManager(t)
	c := saveTestRule(t, m, "grpc.example.com", "collector:4317")
	old := m.routes[c.ID]
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	m.options.ConfigStore = blocker
	changed := c
	changed.Target = "other:4317"
	if _, err := m.Save(changed); err == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if err := m.Delete(c.ID); err == nil {
		t.Fatal("delete unexpectedly succeeded")
	}
	if err := m.SetEnabled(c.ID, false); err == nil {
		t.Fatal("stop unexpectedly succeeded")
	}
	if m.routes[c.ID] != old || old.ctx.Err() != nil || m.List()[0] != c {
		t.Fatal("failed persistence changed live service")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, target := range []string{"", "host", "https://host:4317", "host:0", "host:65536", "http://user:password@host:4317", "host:4317/path", "host:4317?x=1", "host:4317#fragment"} {
		t.Run(target, func(t *testing.T) {
			if _, err := normalizeConfig(Config{Domain: "grpc.example.com", Target: target}); err == nil {
				t.Fatalf("accepted target %q", target)
			}
		})
	}
	for _, domain := range []string{"", "*.example.com", "https://example.com", "example.com:443", "127.0.0.1", "a..com", "bad_name.com"} {
		if _, err := normalizeConfig(Config{Domain: domain, Target: "collector:4317"}); err == nil {
			t.Fatalf("accepted domain %q", domain)
		}
	}
	if _, err := normalizeConfig(Config{Domain: "grpc.example.com", Target: "[::1]:4317"}); err != nil {
		t.Fatal(err)
	}
}

func TestDomainMatchingAndACME(t *testing.T) {
	m := testManager(t)
	saveTestRule(t, m, "grpc.example.com", "collector:4317")
	for _, tc := range []struct {
		host, path string
		match      bool
	}{
		{"grpc.example.com:443", "/service/method", true},
		{"GRPC.EXAMPLE.COM.", "/", true},
		{"other.example.com", "/", false},
		{"sub.grpc.example.com", "/", false},
		{"grpc.example.com", "/.well-known/acme-challenge/token", false},
	} {
		r := httptest.NewRequest("POST", "https://example.com"+tc.path, nil)
		r.Host = tc.host
		if m.Matches(r) != tc.match {
			t.Errorf("match %s%s", tc.host, tc.path)
		}
	}
}

func TestCorruptSavedConfigurationIsRejected(t *testing.T) {
	m := testManager(t)
	path := filepath.Join(m.options.ConfigStore, "routes.json")
	if err := os.WriteFile(path, []byte(`{"Version":1,"Rules":[{"ID":"bad","Domain":"grpc.example.com","Target":"collector:4317"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if restored, err := NewManager(m.options); err == nil {
		restored.Close()
		t.Fatal("invalid saved rule was silently accepted")
	}
}

func TestManagementHandlers(t *testing.T) {
	m := testManager(t)
	for _, handler := range []http.HandlerFunc{m.HandleSave, m.HandleEnabled, m.HandleDelete} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("mutation allowed GET: %d", w.Code)
		}
	}
	for _, payload := range []string{`{"Domain":"grpc.example.com","Unknown":"x"}`, `{}`, `null`, `{} {}`, strings.Repeat("x", 17000)} {
		w := httptest.NewRecorder()
		m.HandleSave(w, httptest.NewRequest("POST", "/", strings.NewReader(payload)))
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result["error"] == nil {
			t.Fatalf("invalid error JSON: %s", w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	m.HandleSave(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"Domain":"grpc.example.com","Target":"collector:4317","Enabled":true}`)))
	var saved Config
	if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil || saved.ID == "" {
		t.Fatalf("save: %s", w.Body.String())
	}
	if len(m.List()) != 1 {
		t.Fatal("save did not persist config")
	}

	w = httptest.NewRecorder()
	m.HandleEnabled(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"ID":"`+saved.ID+`","Enabled":false}`)))
	if m.List()[0].Enabled {
		t.Fatalf("stop failed: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	m.HandleDelete(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"ID":"`+saved.ID+`"}`)))
	if len(m.List()) != 0 {
		t.Fatalf("delete failed: %s", w.Body.String())
	}
}

func TestConcurrentRoutingAndEdits(t *testing.T) {
	m := testManager(t)
	c := saveTestRule(t, m, "grpc.example.com", "collector:4317")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if !m.OwnsDomain(c.Domain) || len(m.List()) != 1 {
					t.Error("domain disappeared")
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if err := m.SetEnabled(c.ID, i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}
