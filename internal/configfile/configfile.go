// Package configfile edits the YAML config in place for the CLI helpers.
//
// It works on the yaml.v3 node tree rather than on decoded structs, so existing
// comments, ordering and flow-style entries survive an edit.
package configfile

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// File is a config file loaded for editing.
type File struct {
	path string
	doc  *yaml.Node // DocumentNode
	mode fs.FileMode

	existed bool
}

// Load reads path. A missing file yields an empty document that Save will create.
func Load(path string) (*File, error) {
	f := &File{path: path, mode: 0o600}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		b = nil
	case err != nil:
		return nil, err
	default:
		f.existed = true
		if st, err := os.Stat(path); err == nil {
			f.mode = st.Mode().Perm()
		}
	}

	var doc yaml.Node
	if len(bytes.TrimSpace(b)) > 0 {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: top level must be a mapping", path)
	}
	f.doc = &doc
	return f, nil
}

// Save writes the file atomically, keeping its permissions (0600 for new files).
func (f *File) Save() error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f.doc); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".config-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(f.mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.path)
}

// Provider is the subset of provider settings the CLI writes.
type Provider struct {
	Name       string `yaml:"name"`
	BaseURL    string `yaml:"base_url"`
	APIKey     string `yaml:"api_key,omitempty"`
	AuthHeader string `yaml:"auth_header,omitempty"`
	AuthScheme string `yaml:"auth_scheme,omitempty"`
	// SessionHeader: see config.Provider.SessionHeader.
	SessionHeader string `yaml:"session_header,omitempty"`
	Auth          string `yaml:"auth,omitempty"`
	External      bool   `yaml:"external,omitempty"`
	Peer          bool   `yaml:"peer,omitempty"`
	CAFile        string `yaml:"ca_file,omitempty"`
}

// APIKey is a client key entry.
type APIKey struct {
	Name   string   `yaml:"name"`
	Hash   string   `yaml:"hash"`
	Models []string `yaml:"models,flow"`
	Admin  bool     `yaml:"admin,omitempty"`
	// Providers: /provider/<name>/ access (see config.APIKey.Providers).
	Providers []string `yaml:"providers,flow,omitempty"`
	// LocalOnly: see config.APIKey.LocalOnly.
	LocalOnly bool `yaml:"local_only,omitempty"`
}

// Entry is a list item summary for `list` commands.
type Entry = map[string]any

// AddProvider appends a provider; the name must be new.
func (f *File) AddProvider(p Provider) error { return f.add("providers", p.Name, p) }

// AddAPIKey appends a client key; the name must be new.
func (f *File) AddAPIKey(k APIKey) error { return f.add("api_keys", k.Name, k) }

// Remove deletes the named item from section ("providers" or "api_keys").
// It reports whether an item was removed.
func (f *File) Remove(section, name string) bool {
	seq := f.seq(section, false)
	if seq == nil {
		return false
	}
	for i, item := range seq.Content {
		if itemName(item) == name {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return true
		}
	}
	return false
}

func (f *File) add(section, name string, v any) error {
	seq := f.seq(section, true)
	for _, item := range seq.Content {
		if itemName(item) == name {
			return fmt.Errorf("%s: %q already exists", section, name)
		}
	}
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return err
	}
	seq.Content = append(seq.Content, &n)
	return nil
}

// List decodes every item of a top-level sequence ("providers", "api_keys", "models").
func (f *File) List(section string) ([]Entry, error) {
	seq := f.seq(section, false)
	if seq == nil {
		return nil, nil
	}
	out := make([]Entry, 0, len(seq.Content))
	for _, item := range seq.Content {
		var e Entry
		if err := item.Decode(&e); err != nil {
			return nil, fmt.Errorf("%s: %w", section, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// seq returns the sequence under a top-level key, creating it if asked.
func (f *File) seq(key string, create bool) *yaml.Node {
	root := f.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			v := root.Content[i+1]
			if v.Kind == yaml.SequenceNode {
				return v
			}
			if !create {
				return nil
			}
			// "key:" with no value (null): replace with an empty block sequence.
			*v = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			return v
		}
	}
	if !create {
		return nil
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, seq)
	return seq
}

func itemName(item *yaml.Node) string {
	if item.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value == "name" {
			return item.Content[i+1].Value
		}
	}
	return ""
}

// Scalar returns a top-level scalar value, or "" if absent.
func (f *File) Scalar(key string) string {
	root := f.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key && root.Content[i+1].Kind == yaml.ScalarNode {
			return root.Content[i+1].Value
		}
	}
	return ""
}

// SetScalar sets a top-level scalar. A new key is inserted at the top of the
// file, with comment as its head comment.
func (f *File) SetScalar(key, value, comment string) {
	root := f.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
			return
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key, HeadComment: comment}
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	// Keep a leading file comment (attached to the first key) at the very top.
	if len(root.Content) > 0 && root.Content[0].HeadComment != "" {
		k.HeadComment, root.Content[0].HeadComment = root.Content[0].HeadComment+"\n\n"+comment, ""
	}
	root.Content = append([]*yaml.Node{k, v}, root.Content...)
}

// Field returns a scalar field of the named item in section, or "".
func (f *File) Field(section, name, field string) string {
	if n := f.fieldNode(section, name, field); n != nil {
		return n.Value
	}
	return ""
}

// SetField sets a scalar field of the named item, adding the field if missing.
// It reports whether the item exists.
func (f *File) SetField(section, name, field, value string) bool {
	seq := f.seq(section, false)
	if seq == nil {
		return false
	}
	for _, item := range seq.Content {
		if itemName(item) != name {
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value == field {
				item.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
				return true
			}
		}
		item.Content = append(item.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		return true
	}
	return false
}

func (f *File) fieldNode(section, name, field string) *yaml.Node {
	seq := f.seq(section, false)
	if seq == nil {
		return nil
	}
	for _, item := range seq.Content {
		if itemName(item) != name {
			continue
		}
		for i := 0; i+1 < len(item.Content); i += 2 {
			if item.Content[i].Value == field && item.Content[i+1].Kind == yaml.ScalarNode {
				return item.Content[i+1]
			}
		}
	}
	return nil
}

// Exists reports whether the file was present on disk when loaded.
func (f *File) Exists() bool { return f.existed }

// SetMapping sets a top-level key to a mapping encoded from v, appending it if new.
func (f *File) SetMapping(key string, v any) error {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return err
	}
	root := f.doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			root.Content[i+1] = &n
			return nil
		}
	}
	root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &n)
	return nil
}

// WalkScalars calls fn for every scalar value node in the document (not keys).
// fn may change the node's Value in place.
func (f *File) WalkScalars(fn func(n *yaml.Node)) {
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1])
			}
		case yaml.ScalarNode:
			fn(n)
		}
	}
	walk(f.doc)
}

// MapAt returns the mapping at the given key path (e.g. "server", "tls",
// "acme", "dns_env"), creating missing levels when create is set. It returns
// nil if the path is missing (or not a mapping) and create is false.
func (f *File) MapAt(create bool, path ...string) *yaml.Node {
	n := f.doc.Content[0]
	for _, key := range path {
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		if next == nil || next.Kind != yaml.MappingNode {
			if !create {
				return nil
			}
			m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			if next != nil { // e.g. "key:" with a null value
				*next = *m
			} else {
				n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, m)
				next = m
			}
		}
		n = next
	}
	return n
}

// SetIn sets key to a string value in the mapping at path (created as needed).
func (f *File) SetIn(path []string, key, value string) {
	m := f.MapAt(true, path...)
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// RemoveIn deletes key from the mapping at path; it reports whether it existed.
func (f *File) RemoveIn(path []string, key string) bool {
	m := f.MapAt(false, path...)
	if m == nil {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// KeysIn lists the keys of the mapping at path, with their values.
func (f *File) KeysIn(path ...string) [][2]string {
	m := f.MapAt(false, path...)
	if m == nil {
		return nil
	}
	var out [][2]string
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, [2]string{m.Content[i].Value, m.Content[i+1].Value})
	}
	return out
}
