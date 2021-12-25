package policybench

import (
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"denkruum.ch/policybench/internal/auth/casbin"
	"denkruum.ch/policybench/internal/auth/opa"
	"denkruum.ch/policybench/internal/auth/polar"

	"denkruum.ch/policybench/internal/auth"
)

var (
	casbinAuth    auth.Authorizer
	opaAuth       auth.Authorizer
	polarAuth     auth.Authorizer
	testUserName  string
	policiesCount *int  = flag.Int("count", 100, "use to generate benchmark files with <count> number of policies")
	newData       *bool = flag.Bool("new-data", false, "specify true to create new policies")
)

const (
	testDataPath          = "internal/data/"
	regoPolicyNameTempl   = "%spolicy_%d.json"
	casbinPolicyNameTempl = "%spolicy_%d.csv"
	polarPolicyNameTempl  = "%spolicy_%d.polar"
)

func TestMain(m *testing.M) {
	flag.Parse()
	regoPolicyFile := fmt.Sprintf(regoPolicyNameTempl, testDataPath, *policiesCount)
	casbinPolicyFile := fmt.Sprintf(casbinPolicyNameTempl, testDataPath, *policiesCount)
	polarPolicyFile := fmt.Sprintf(polarPolicyNameTempl, testDataPath, *policiesCount)
	log.Println("Setting up benchmark environment...")
	// check newData flag and try to re-use existing json (rego) if desired
	reuse := *newData
	ua := SetUpPolicyData(newData, uint(*policiesCount), regoPolicyFile)
	if reuse != *newData { // was changed by SetUpPolicyData
		log.Print("Couldn't re-use behchnmark data! \n")
	}
	if *newData {
		log.Printf("Created %d ACL entries", len(ua))
	}
	err := SetUpPolicyFile(*newData, regoPolicyFile, ua, WriteJSON)
	NoErrorf(err, "failure initializing policy test file %s, err: %v", regoPolicyFile, err)
	err = SetUpPolicyFile(*newData, casbinPolicyFile, ua, WriteCSV)
	NoErrorf(err, "failure initializing policy test file %s, err: %v", casbinPolicyFile, err)
	err = SetUpPolicyFile(*newData, polarPolicyFile, ua, WritePolarRules)
	NoErrorf(err, "failure initializing policy test file %s, err: %v", polarPolicyFile, err)

	casbinAuth = casbin.New(testDataPath+"model.conf", casbinPolicyFile)
	opaAuth, err = opa.New(testDataPath+"proglog.rego", regoPolicyFile)
	NoErrorf(err, "failure initializing OPA: %v", err)
	polarAuth, err = polar.New(polarPolicyFile, "")
	NoErrorf(err, "failure initializing OSO: %v", err)
	testUserName = GetRndUser(ua)
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

func BenchmarkPolarExistingAction(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = polarAuth.Authorize(testUserName, "*", "consume")
	}
}

func BenchmarkPolarWrongUser(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = opaAuth.Authorize("not_a_user", "*", "not_an_action")
	}
}
