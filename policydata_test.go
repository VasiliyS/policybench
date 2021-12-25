package policybench

import (
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/MarvinJWendt/testza"
	"github.com/brianvoe/gofakeit/v6"
)

func TestPolicyData(t *testing.T) {
	pd := NewPolicyDataMap(100)
	f, err := os.OpenFile(testDataPath+"policy_100.csv", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("can't open policy file, err: %v", err)
	}
	err = WriteCSV(f, pd)
	safeClose(f, err)
	testza.AssertNoError(t, err)

	f, err = os.OpenFile(testDataPath+"policy_100.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("can't open policy file, err: %v", err)
	}
	err = WriteJSON(f, pd)
	safeClose(f, err)
	testza.AssertNoError(t, err)

	_, err = ReadJSON(testDataPath + "policy_100.json")
	testza.AssertNoError(t, err)

	f, err = os.OpenFile(testDataPath+"policy_100.polar", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("can't open policy file, err: %v", err)
	}
	err = WritePolarRules(f, pd)
	safeClose(f, err)
	testza.AssertNoError(t, err)
}

func TestSelectRandNof(t *testing.T) {
	for iter := 0; iter < 1000; iter++ {
		rand.Seed(time.Now().UnixNano())
		var sourceL int
		for {
			l := rand.Intn(100)
			if l > 2 {
				sourceL = l
				break
			}
		}
		subsetL := rand.Intn(sourceL)
		source := make([]string, sourceL)
		for i, _ := range source {
			source[i] = gofakeit.Regex("[[:word:]]{8,15}") + strconv.Itoa(i)
		}
		subset := selectRandNof(subsetL, source)
		for i, str := range subset {
			for j := i + 1; j < subsetL-1; j++ {
				if str == subset[j] {

					t.Logf(" iter# %d : was selecting random %d of %d\n", iter, subsetL, sourceL)
					t.Fatalf(" found duplicate subset[%d] & subset[%d] are: %s \n", i, j, str)
				}
			}
		}
	}
}
