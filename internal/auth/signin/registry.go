package signin

// Registry 是配置驱动的登录方式注册表。登录页遍历 List() 渲染，提交按 Name 派发 Get()。
type Registry struct {
	order  []SigninMethod
	byName map[string]SigninMethod
}

// NewRegistry 按给定顺序装配登录方式（顺序即登录页渲染顺序）。重名后者覆盖前者。
func NewRegistry(methods ...SigninMethod) *Registry {
	r := &Registry{byName: make(map[string]SigninMethod, len(methods))}
	for _, m := range methods {
		if _, exists := r.byName[m.Name()]; !exists {
			r.order = append(r.order, m)
		}
		r.byName[m.Name()] = m
	}
	return r
}

// List 返回登录方式列表（渲染顺序）。
func (r *Registry) List() []SigninMethod {
	return r.order
}

// Get 按名取登录方式。found=false 表示未注册。
func (r *Registry) Get(name string) (SigninMethod, bool) {
	m, ok := r.byName[name]
	return m, ok
}
