package opa

import (
	"context"
	"fmt"

	"denkruum.ch/policybench/internal/auth"
	"github.com/open-policy-agent/opa/rego"
)

type authorizer struct {
	q rego.PreparedEvalQuery
}

func New(rules, data string) (auth.Authorizer, error) {
	r := rego.New(
		rego.Query("data.proglog.allow"),
		rego.Load([]string{rules, data}, nil),
	)
	ctx := context.Background()
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &authorizer{q: query}, nil
}

func (a *authorizer) Authorize(subj, obj, act string) error {

	ctx := context.TODO()
	input := map[string]interface{}{"id": subj, "action": act}
	rs, err := a.q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return err
	}
	if !rs[0].Expressions[0].Value.(bool) {
		return fmt.Errorf("subj %s not permitted action %s on %s", subj, act, obj)
	}
	return nil
}
