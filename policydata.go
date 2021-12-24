package policybench

import (
	"encoding/csv"
	"encoding/json"
	"github.com/brianvoe/gofakeit/v6"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"
)

type policyData struct {
	User           string   `fake:"{regex:[[:word:]]{8,15}}" json:"user,omitempty"`
	AllowedActions []string `fake:"skip" json:"omitempty"`
}

func NewPolicyData(count uint) []*policyData {
	pd := make([]*policyData, count)
	actions := []string{"produce", "consume", "none"}
	for i := range pd {
		pd[i] = &policyData{}
		err := gofakeit.Struct(pd[i])
		if err != nil {
			log.Fatalf("failed to create test policy: %v\n", err)
		}
		pd[i].User = pd[i].User + strconv.Itoa(i) // make sure these are unique
		pd[i].AllowedActions = selectRandNof(2, actions)

	}
	return pd
}

func GetRndUser(pd []*policyData) string {
	rand.Seed(time.Now().UnixNano())
	rInd := rand.Intn(len(pd))
	return pd[rInd].User
}

func WriteCSV(f *os.File, policies []*policyData) error {
	w := csv.NewWriter(f)
	for _, p := range policies {
		for _, act := range p.AllowedActions {
			r := []string{"p", p.User, "*", act}
			err := w.Write(r)
			if err != nil {
				return err
			}
		}
	}
	w.Flush()
	return nil
}

func WriteJSON(f *os.File, policies []*policyData) error {
	// { "<user>":["act1","act2",..]}
	users := make(map[string][]string)
	for _, p := range policies {
		users[p.User] = p.AllowedActions
	}

	e := json.NewEncoder(f)
	// { "users": { "<user1>": ["act1,..,"actn"],..,"<userN>":["act1",..,"actN"]}}
	regoPolicies := map[string]interface{}{"users": users}

	err := e.Encode(regoPolicies)
	if err != nil {
		return err
	}
	return nil
}

func SetUpPolicyFile(newData bool, file string, pd []*policyData, wf func(*os.File, []*policyData) error) error {
	var (
		pf *os.File
		wErr   error
	)
	fFlags := os.O_CREATE | os.O_WRONLY
	switch _, err := os.Stat(file); {
	case err == nil && newData == false:  //file exists & should be re-used
		log.Printf("Re-using exiting policies file: %s \n", file)
		return nil
	case err == nil && newData: // file exists & should be re-written
		fFlags |= os.O_TRUNC
		log.Printf("Exisitng policy file: %s will be re-written \n", file)
		fallthrough
	case err != nil:
		pf, err = os.OpenFile(file,fFlags,0644)
		if err != nil {
			return err
		}
		wErr = wf(pf, pd)
		if wErr != nil {
			log.Println("Finished writing policies!")
		}
	}
	safeClose(pf, wErr)
	return wErr
}

