// Package repositoryroutepolicy loads the reviewed local repository routing manifest.
package repositoryroutepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const Version = "repository-route-policy/v1"

type Manifest struct {
	Version string  `yaml:"version" json:"version"`
	Routes  []Route `yaml:"routes" json:"routes"`
}

type Route struct {
	Repository        string `yaml:"repository" json:"repository"`
	BackendURL        string `yaml:"backend_url" json:"backend_url"`
	WritableNamespace string `yaml:"writable_namespace" json:"writable_namespace"`
}

type Policy struct {
	Manifest     Manifest
	Digest       string
	byRepository map[string]Route
}

func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator supplied config path.
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m.Version != Version {
		return nil, fmt.Errorf("repository route policy version must be %q", Version)
	}
	if len(m.Routes) == 0 {
		return nil, errors.New("repository route policy routes must not be empty")
	}
	sort.Slice(m.Routes, func(i, j int) bool { return m.Routes[i].Repository < m.Routes[j].Repository })
	p := &Policy{Manifest: m, byRepository: make(map[string]Route, len(m.Routes))}
	for _, route := range m.Routes {
		if !regexp.MustCompile(`^local/[a-z0-9][a-z0-9_.-]{0,79}$`).MatchString(route.Repository) {
			return nil, fmt.Errorf("invalid local repository %q", route.Repository)
		}
		if !strings.HasPrefix(route.BackendURL, "http://") && !strings.HasPrefix(route.BackendURL, "https://") {
			return nil, fmt.Errorf("route %q backend_url must be http(s)", route.Repository)
		}
		if !regexp.MustCompile(`^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*/*$`).MatchString(route.WritableNamespace) {
			return nil, fmt.Errorf("route %q has invalid writable_namespace", route.Repository)
		}
		if _, exists := p.byRepository[route.Repository]; exists {
			return nil, fmt.Errorf("duplicate local repository %q", route.Repository)
		}
		p.byRepository[route.Repository] = route
	}
	canonical, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canonical)
	p.Digest = hex.EncodeToString(sum[:])
	return p, nil
}

func (p *Policy) Route(repository string) (Route, bool) {
	route, ok := p.byRepository[repository]
	return route, ok
}
