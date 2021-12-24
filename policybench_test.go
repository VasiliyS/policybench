package policybench

import (
	"denkruum.ch/policybench/internal/auth/casbin"
	"denkruum.ch/policybench/internal/auth/opa"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"denkruum.ch/policybench/internal/auth"
)

var (
	casbinAuth auth.Authorizer
	opaAuth    auth.Authorizer
	testUserName  string
	policiesCount *int  = flag.Int("count",100, "use to generate benchmark files with <count> number of policies")
	newData       *bool = flag.Bool("new-data", false, "specify true to create new policies")
)


const (
	testDataPath = "internal/data/"
	regoPolicyNameTempl = "%spolicy_%d.json"
	casbinPolicyNameTempl = "%spolicy_%d.csv"
)


func TestMain(m *testing.M){
	flag.Parse()
	regoPolicyFile := fmt.Sprintf(regoPolicyNameTempl,testDataPath, *policiesCount)
	casbinPolicyFile := fmt.Sprintf(casbinPolicyNameTempl,testDataPath, *policiesCount)
	log.Println("Setting up benchmark environment...")
	pd := NewPolicyData(uint(*policiesCount))
	log.Printf("Created %d new policies",len(pd))
	err := SetUpPolicyFile(*newData,regoPolicyFile,pd,WriteJSON)
	NoErrorf(err,"failure initializing policy test file %s, err: %v", regoPolicyFile,err)
	err = SetUpPolicyFile(*newData,casbinPolicyFile,pd,WriteCSV)
	NoErrorf(err, "failure initializing policy test file %s, err: %v", casbinPolicyFile,err)

	casbinAuth = casbin.New(testDataPath+"model.conf", casbinPolicyFile)
	opaAuth, err = opa.New(testDataPath+"proglog.rego", regoPolicyFile)
	NoErrorf(err,"failure initializing OPA: %v", err)
	testUserName = GetRndUser(pd)
	log.Printf("Ready to run benchmark!")
	os.Exit(m.Run())
}

func BenchmarkCasbinExisitngUser(b *testing.B) {

	for n := 0; n < b.N; n++ {
		_ = casbinAuth.Authorize(testUserName, "", "consume")
	}
}

func BenchmarkCasbinWrongUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = casbinAuth.Authorize("not_a_user", "", "not_an_action")
	}
}
func BenchmarkOPAExistingAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize(testUserName, "", "consume")
	}
}


func BenchmarkOPAWrongUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize("not_a_user", "", "not_an_action")
	}
}
