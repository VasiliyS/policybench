package policybench

import (
	"log"
	"math/rand"
	"os"
	"time"
)

func NoErrorf(err error, msgf string, opts ...interface{} ){
	if err != nil {
		log.Fatalf(msgf, opts...)
	}
}

func safeClose(f *os.File, err error) { // in case writing to CSV file fails
	errC := f.Close()
	if errC != nil {
		log.Printf("failed closing policy file: %s error: %v ", f.Name(), errC)
		return
	}
	if err != nil {
		errR := os.Remove(f.Name())
		log.Printf("failed removing incomplete policy file %s, error: %v", f.Name(), errR)
		return
	}
}

func selectRandNof(n int, slice []string) []string {
	l := len(slice)
	ind := make([]int, n) // random set of indices from slice
	rand.Seed(time.Now().UnixNano())
	var rInd int
	res := make([]string, n)
	for i := 0; i < n; i++ {
	Newrand:
		for {
			rInd = rand.Intn(l)
			for j := 0; j < i; j++ { // check that new index is unique so far
				if ind[j] == rInd {
					continue Newrand // keep looking for a new unique index
				}
			}
			break // unique rInd found
		}
		ind[i] = rInd
		res[i] = slice[rInd]
	}

	//for i := 0; i < n; i++ {
	//	res[i]=slice[ind[i]]
	//}
	return res
}
