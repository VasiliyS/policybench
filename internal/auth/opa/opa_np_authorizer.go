package opa

import (
	"context"
	"fmt"

	"denkruum.ch/policybench/internal/auth"
	"github.com/open-policy-agent/opa/rego"
)

type authorizerNP struct {
	r *rego.Rego
}

func NewNP(rules, data string) (auth.Authorizer, error) {
	r := rego.New(
		rego.Query("data.proglog.allow"),
		rego.Load([]string{rules, data}, nil),
	)
	return &authorizerNP{r: r}, nil
}

func (a *authorizerNP) Authorize(subj, obj, act string) error {

	ctx := context.TODO()
	input := map[string]interface{}{"id": subj, "action": act}
	query, err := a.r.PrepareForEval(ctx)
	if err != nil {
		return err
	}
	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return err
	}
	if !rs[0].Expressions[0].Value.(bool) {
		return fmt.Errorf("subj %s not permitted action %s on %s", subj, act, obj)
	}
	return nil
}
