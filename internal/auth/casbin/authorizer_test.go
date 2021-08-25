package casbin

import (
	"testing"

	"github.com/MarvinJWendt/testza"
)

const (
	dataPath = "../../data/"
)

func TestAuthorizer(t *testing.T) {
	enf := New(dataPath+"model.conf", dataPath+"policy.csv")
	err := enf.Authorize("root", "*", "consume")
	testza.AssertNoError(t, err)

}
