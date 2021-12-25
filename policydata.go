package policybench

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

/*
type policyData struct {
	User           string   `fake:"{regex:[[:word:]]{8,15}}" json:"user,omitempty"`
	AllowedActions []string `fake:"skip" json:"omitempty"`
}
*/

type allowedUserActions map[string][]string

func SetUpPolicyData(newData *bool, noOfRecords uint, jsonPolFile string) allowedUserActions {
	if *newData {
		return NewPolicyDataMap(noOfRecords)
	}
	// try to read from json
	pd, err := ReadJSON(jsonPolFile)
	if err != nil {
		// problem with the file, cant'use
		*newData = true
		return NewPolicyDataMap(noOfRecords)
	}
	return pd
}

/*
// func NewPolicyData(count uint) []*policyData {
// 	pd := make([]*policyData, count)
// 	actions := []string{"produce", "consume", "none"}
// 	for i := range pd {
// 		pd[i] = &policyData{}
// 		err := gofakeit.Struct(pd[i])
// 		if err != nil {
// 			log.Fatalf("failed to create test policy: %v\n", err)
// 		}
// 		pd[i].User = pd[i].User + strconv.Itoa(i) // make sure these are unique
// 		pd[i].AllowedActions = selectRandNof(2, actions)

// 	}
// 	return pd
// }
*/

func NewPolicyDataMap(count uint) allowedUserActions {
	ua := make(map[string][]string)
	actions := []string{"produce", "consume", "none"}
	for i := uint(0); i < count; i++ {
		userName := gofakeit.Regex("[[:word:]]{8,15}") + strconv.FormatUint(uint64(i), 10) // make sure these are unique
		ua[userName] = selectRandNof(2, actions)
	}
	return ua
}

/*
func GetRndUser(pd []*policyData) string {
	rand.Seed(time.Now().UnixNano())
	rInd := rand.Intn(len(pd))
	return pd[rInd].User
}
*/

func GetRndUser(ua allowedUserActions) string {
	rand.Seed(time.Now().UnixNano())
	rInd := rand.Intn(len(ua))
	var userName string
	for userName = range ua {
		if rInd == 0 {
			break
		}
		rInd--
	}
	return userName
}

func WriteCSV(f *os.File, ua allowedUserActions) error {
	w := csv.NewWriter(f)
	for userName := range ua {
		for _, act := range ua[userName] {
			r := []string{"p", userName, "*", act}
			err := w.Write(r)
			if err != nil {
				return err
			}
		}
	}
	w.Flush()
	return nil
}

func WriteJSON(f *os.File, ua allowedUserActions) error {
	e := json.NewEncoder(f)
	// { "users": { "<user1>": ["act1,..,"actn"],..,"<userN>":["act1",..,"actN"]}}
	regoPolicies := map[string]interface{}{"users": ua}

	err := e.Encode(regoPolicies)
	if err != nil {
		return err
	}
	return nil
}
func ReadJSON(jsonPolFile string) (allowedUserActions, error) {
	f, err := os.Open(jsonPolFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	rr := make(map[string]allowedUserActions)
	err = d.Decode(&rr)
	if err != nil {
		return nil, err
	}
	ua := rr["users"]
	if ua == nil {
		return nil, fmt.Errorf("wrong JSON file format, key \"users\" is missing, file %s:  ", jsonPolFile)
	}
	return rr["users"], nil
}

//WritePolarRules creates an ACL using Polar langauge: allow("user","act","*");
func WritePolarRules(f *os.File, ua allowedUserActions) error {
	for userName := range ua {
		for _, act := range ua[userName] {
			_, err := f.WriteString(fmt.Sprintf("allow(%q,%q,\"*\");\n", userName, act))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func SetUpPolicyFile(newData bool, file string, ua allowedUserActions, wf func(*os.File, allowedUserActions) error) error {
	var (
		pf   *os.File
		wErr error
	)
	fFlags := os.O_CREATE | os.O_WRONLY
	switch _, err := os.Stat(file); {
	case err == nil && !newData: //file exists & should be re-used
		log.Printf("Re-using exiting policies file: %s \n", file)
		return nil
	// case err != nil && !newData: // wanted to re-use but file is missing
	// 	log.Printf("Can't re-use policy file: %s, please rerun the benchmark with the 'new-data' flag\n", file)
	// 	return err
	case err == nil && newData: // file exists & should be re-written
		fFlags |= os.O_TRUNC
		log.Printf("Existing policy file: %s will be re-written \n", file)
		fallthrough
	case err != nil:
		pf, err = os.OpenFile(file, fFlags, 0644)
		if err != nil {
			return err
		}
		log.Printf("Preparing to write %d policies to file %s \n", len(ua), file)
		wErr = wf(pf, ua)
		if wErr == nil {
			log.Println("Finished writing policies!")
		}
	}
	safeClose(pf, wErr)
	return wErr
}
