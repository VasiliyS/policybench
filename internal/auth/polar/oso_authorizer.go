package polar

import (
	"fmt"

	"denkruum.ch/policybench/internal/auth"
	"github.com/osohq/go-oso"
)

type authorizer struct {
	o oso.Oso
}

//New - creates Oso instance, no use for teh data as ACL are all in the policy file
func New(rules, _ string) (auth.Authorizer, error) {
	o, err := oso.NewOso()
	if err != nil {
		return nil, err
	}
	err = o.LoadFiles([]string{rules})
	if err != nil {
		return nil, err
	}

	return &authorizer{o: o}, nil

}

func (a *authorizer) Authorize(subj, obj, act string) error {

	err := a.o.Authorize(subj, act, obj)
	if err != nil {
		return fmt.Errorf("subj %s not permitted action %s on %s, err: %w", subj, act, obj, err)
	}
	return nil
}
