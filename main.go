package vmprotect

import (
	"errors"
	"fmt"
	"math/big"
	"time"
)

type License struct {
	Name, Email          string
	Expiration, MaxBuild time.Time
	HardwareId           []byte
	RunningTimeLimit     int
	UserData             []byte
}

func ParseLicense(serial, public, modulus, productCode string, bits int) (*License, error) {
	return nil, errors.New("not implemented")
}

func base10Encode(str string) (string) {
	var result = big.NewInt(0)
    for _, r := range str {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(r)))
    }

	return result.String()
}


func base10Decode(str string) (string) {
	var data = new(big.Int)
	if _, succ := data.SetString(str, 10); !succ {
		fmt.Printf("Error base10Decode: %v", str)
	}

	var res string
	for {
		if data.Cmp(big.NewInt(0)) <= 0 { break }
		var m = new(big.Int)
		data.DivMod(data, big.NewInt(256), m)
		res =  string(m.Uint64()) + res
	}

	return res
}
