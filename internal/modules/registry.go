package modules

type Registry struct {
	modules []Module
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.Register(&SSHModule{})
	return r
}

func (r *Registry) Register(m Module) {
	r.modules = append(r.modules, m)
}

func (r *Registry) All() []Module {
	return r.modules
}
