package policybench_test

import (
	"log"
	"testing"

	"denkruum.ch/policybench/internal/auth"
	"denkruum.ch/policybench/internal/auth/casbin"
	"denkruum.ch/policybench/internal/auth/opa"
)

var (
	casbinAuth auth.Authorizer
	opaAuth    auth.Authorizer
	opaNPAuth  auth.Authorizer
)

const (
	testDataPath = "internal/data/"
)

func init() {
	casbinAuth = casbin.New(testDataPath+"model.conf", testDataPath+"policy.csv")
	var err error
	opaAuth, err = opa.New(testDataPath+"proglog.rego", testDataPath+"proglog.json")
	if err != nil {
		log.Fatalf("error initializing OPA %v", err)
	}
	opaNPAuth, err = opa.NewNP(testDataPath+"proglog.rego", testDataPath+"proglog.json")
	if err != nil {
		log.Fatalf("error initializing OPA %v", err)
	}
	log.Println("Test is set-up, redy to execute....")
}

func BenchmarkCasbinExisitngAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = casbinAuth.Authorize("root", "", "consume")
	}
}

func BenchmarkCasbinWrongAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = casbinAuth.Authorize("root", "", "not_an_action")
	}
}

func BenchmarkCasbinWrongUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = casbinAuth.Authorize("not_a_user", "", "not_an_action")
	}
}
func BenchmarkOPAExistingAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize("root", "", "consume")
	}
}

func BenchmarkOPAWrongAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize("root", "", "not_an_action")
	}
}

func BenchmarkOPAWrongUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize("not_a_user", "", "not_an_action")
	}
}

func BenchmarkOPANPExistingAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaNPAuth.Authorize("root", "", "consume")
	}
}
