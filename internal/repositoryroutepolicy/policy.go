// Package repositoryroutepolicy loads the reviewed local repository routing manifest.
package repositoryroutepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
	Repository      string   `yaml:"repository" json:"repository"`
	BackendURL      string   `yaml:"backend_url" json:"backend_url"`
	ReadableRefs    []string `yaml:"readable_refs" json:"readable_refs"`
	WritableRefs    []string `yaml:"writable_refs" json:"writable_refs"`
	FastForwardOnly bool     `yaml:"fast_forward_only" json:"fast_forward_only"`
	NoDelete        bool     `yaml:"no_delete" json:"no_delete"`
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
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&m); err != nil {
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
		u, err := url.Parse(route.BackendURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("route %q backend_url must be an http(s) origin without credentials, path, query, or fragment", route.Repository)
		}
		if !exactRefs(route.ReadableRefs, []string{"refs/heads/main", "refs/heads/agent/repository-proof/**"}) || !exactRefs(route.WritableRefs, []string{"refs/heads/agent/repository-proof/**"}) || !route.FastForwardOnly || !route.NoDelete {
			return nil, fmt.Errorf("route %q does not satisfy the repository lifecycle ref contract", route.Repository)
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

func exactRefs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(got))
	for _, ref := range got {
		if !regexp.MustCompile(`^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]*(/\*\*)?$`).MatchString(ref) || seen[ref] {
			return false
		}
		seen[ref] = true
	}
	for _, ref := range want {
		if !seen[ref] {
			return false
		}
	}
	return true
}

// AllowsWrite reports whether ref is one of the reviewed writable refs.
func (r Route) AllowsWrite(ref string) bool {
	for _, allowed := range r.WritableRefs {
		if strings.HasSuffix(allowed, "/**") && strings.HasPrefix(ref, strings.TrimSuffix(allowed, "**")) {
			return true
		}
		if ref == allowed {
			return true
		}
	}
	return false
}

func (p *Policy) Route(repository string) (Route, bool) {
	route, ok := p.byRepository[repository]
	return route, ok
}
