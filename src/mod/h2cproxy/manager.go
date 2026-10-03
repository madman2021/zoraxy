package h2cproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/google/uuid"
	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/info/logger"
)

type Options struct {
	ConfigStore      string
	AccessController *access.Controller
	Logger           *logger.Logger
}

// Manager owns domain reservations and running services. Configuration changes
// are serialized and persisted before the live routing table is replaced.
type Manager struct {
	mu      sync.RWMutex
	options Options
	routes  map[string]*service // keyed by config ID
	domains map[string]*service
	closed  bool
}

type configFile struct {
	Version int
	Rules   []Config
}

func NewManager(options Options) (*Manager, error) {
	if options.ConfigStore == "" || options.AccessController == nil {
		return nil, errors.New("h2c proxy requires a configuration directory and access controller")
	}
	if err := os.MkdirAll(options.ConfigStore, 0750); err != nil {
		return nil, err
	}
	m := &Manager{options: options, routes: map[string]*service{}, domains: map[string]*service{}}
	data, err := os.ReadFile(filepath.Join(options.ConfigStore, "routes.json"))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var saved configFile
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("read h2c configuration: %w", err)
	}
	if saved.Version != 1 {
		return nil, errors.New("unsupported h2c configuration version")
	}
	for _, c := range saved.Rules {
		c, err = normalizeConfig(c)
		if err == nil {
			_, err = uuid.Parse(c.ID)
		}
		if err != nil || m.routes[c.ID] != nil || m.domains[c.Domain] != nil {
			m.Close()
			return nil, fmt.Errorf("invalid or duplicate h2c rule %q", c.ID)
		}
		s := newService(c)
		m.routes[c.ID] = s
		m.domains[c.Domain] = s
	}
	return m, nil
}

func (m *Manager) List() []Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return sortedConfigs(m.routes)
}

func sortedConfigs(routes map[string]*service) []Config {
	configs := make([]Config, 0, len(routes))
	for _, s := range routes {
		configs = append(configs, s.config)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Domain < configs[j].Domain })
	return configs
}

// Save creates a rule when ID is empty, or replaces an existing rule otherwise.
// Validation and disk failures leave the previous service running.
func (m *Manager) Save(config Config) (Config, error) {
	config, err := normalizeConfig(config)
	if err != nil {
		return Config{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Config{}, errors.New("h2c proxy manager is closed")
	}
	if config.ID == "" {
		config.ID = uuid.NewString()
	} else if m.routes[config.ID] == nil {
		return Config{}, errors.New("h2c rule not found")
	}
	if existing := m.domains[config.Domain]; existing != nil && existing.config.ID != config.ID {
		return Config{}, errors.New("an h2c rule already owns this domain")
	}
	if rule, err := m.options.AccessController.GetAccessRuleByID(config.AccessRuleID); err != nil || rule == nil {
		return Config{}, errors.New("access rule not found")
	}
	return m.replaceLocked(config)
}

func (m *Manager) replaceLocked(config Config) (Config, error) {
	old := m.routes[config.ID]
	next := newService(config)
	routes := m.copyRoutes()
	routes[config.ID] = next
	if err := m.persist(routes); err != nil {
		next.close()
		return Config{}, err
	}
	if old != nil {
		delete(m.domains, old.config.Domain)
		old.close()
	}
	m.routes = routes
	m.domains[config.Domain] = next
	return config, nil
}

// SetEnabled starts or stops the service without releasing its hostname. A
// stopped domain responds with 503 instead of falling into another proxy rule.
func (m *Manager) SetEnabled(id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("h2c proxy manager is closed")
	}
	s := m.routes[id]
	if s == nil {
		return errors.New("h2c rule not found")
	}
	config := s.config
	config.Enabled = enabled
	_, err := m.replaceLocked(config)
	return err
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("h2c proxy manager is closed")
	}
	s := m.routes[id]
	if s == nil {
		return errors.New("h2c rule not found")
	}
	routes := m.copyRoutes()
	delete(routes, id)
	if err := m.persist(routes); err != nil {
		return err
	}
	m.routes = routes
	delete(m.domains, s.config.Domain)
	s.close()
	return nil
}

func (m *Manager) copyRoutes() map[string]*service {
	routes := make(map[string]*service, len(m.routes))
	for id, s := range m.routes {
		routes[id] = s
	}
	return routes
}

func (m *Manager) persist(routes map[string]*service) error {
	data, err := json.MarshalIndent(configFile{Version: 1, Rules: sortedConfigs(routes)}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.options.ConfigStore, ".h2c-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(m.options.ConfigStore, "routes.json"))
}

// Close cancels active streams and closes idle connections without changing the
// saved Enabled state. The next process restores the saved services.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for _, s := range m.routes {
		s.close()
	}
}

func (s *service) close() {
	s.cancel()
	if s.transport != nil {
		s.transport.CloseIdleConnections()
	}
}
