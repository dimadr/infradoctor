package modules

// Registry holds all registered diagnostic modules.
type Registry struct {
	modules []Module
}

// NewRegistry creates a registry with the built-in modules.
func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(&SSHModule{})
	r.Register(&FirewallModule{})
	return r
}

// Register adds a module to the registry.
func (r *Registry) Register(m Module) {
	r.modules = append(r.modules, m)
}

// All returns all registered modules.
func (r *Registry) All() []Module {
	return r.modules
}
