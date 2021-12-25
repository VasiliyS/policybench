package polar

import (
	"testing"

	"github.com/MarvinJWendt/testza"
)

const (
	dataPath = "../../data/"
)

func TestPolarAuthorizer(t *testing.T) {

	oso, err := New(dataPath+"policy_test.polar", "")
	if err != nil {
		t.Fatal(err)
	}
	err = oso.Authorize("root", "*", "consume")
	testza.AssertNoError(t, err)
	err = oso.Authorize("nobody", "*", "consume")
	testza.AssertNotNil(t, err)
	err = oso.Authorize("root", "*", "not_an_action")
	testza.AssertNotNil(t, err)
}
