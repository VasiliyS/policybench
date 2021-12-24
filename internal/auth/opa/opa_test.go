package opa

import (
	"testing"

	"github.com/MarvinJWendt/testza"
)

const (
	dataPath = "../../data/"
)

func TestAuthorizerNP(t *testing.T) {

	rego, err := NewNP(dataPath+"proglog.rego", dataPath+"proglog.json")
	if err != nil {
		t.Fatal(err)
	}
	err = rego.Authorize("root", "", "consume")
	testza.AssertNoError(t, err)
	err = rego.Authorize("nobody", "", "consume")
	testza.AssertNotNil(t, err)
	err = rego.Authorize("root", "", "not_an_action")
	testza.AssertNotNil(t, err)
}
func TestAuthorizer(t *testing.T) {

	rego, err := New(dataPath+"proglog.rego", dataPath+"proglog.json")
	if err != nil {
		t.Fatal(err)
	}
	err = rego.Authorize("root", "", "consume")
	testza.AssertNoError(t, err)
	err = rego.Authorize("nobody", "", "consume")
	testza.AssertNotNil(t, err)
	err = rego.Authorize("root", "", "not_an_action")
	testza.AssertNotNil(t, err)
}
