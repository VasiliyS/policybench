package casbin

import (
	"fmt"

	"denkruum.ch/policybench/internal/auth"
	"github.com/casbin/casbin"
)

type authorizer struct {
	enforcer *casbin.Enforcer
}

func New(model, policy string) auth.Authorizer {
	enforcer := casbin.NewEnforcer(model, policy)
	return &authorizer{enforcer: enforcer}
}

func (a *authorizer) Authorize(subj, obj, act string) error {
	if !a.enforcer.Enforce(subj, obj, act) {
		return fmt.Errorf("subj %s not permitted action %s on %s", subj, act, obj)
	}
	return nil
}
