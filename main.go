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
		fmt.Printf("Error in base10Decode: %v", str)
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

func powmod(_base string, _exponent string, _modulus string) (string) {
	var base = new(big.Int)
	if _, succ := base.SetString(_base, 10); !succ {
		fmt.Printf("Error in powmod, can't convert _base: %v", _base)
	}

	var exponent = new(big.Int)
	if _, succ := exponent.SetString(_exponent, 10); !succ {
		fmt.Printf("Error in powmod, can't convert _exponent: %v", _exponent)
	}

	var modulus = new(big.Int)
	if _, succ := modulus.SetString(_modulus, 10); !succ {
		fmt.Printf("Error in powmod, can't convert _modulus: %v", _modulus)
	}

	var square = new(big.Int)
	var _square = base
	_square.DivMod(base, modulus, square)
	var result = big.NewInt(1)

	for {
		if exponent.Cmp(big.NewInt(0)) <= 0 { break }
		if exponent.Cmp(big.NewInt(2)) != 0 {
			var _result = result
			_result.DivMod(_result.Mul(_result, square), modulus, result)
		}

		var _square = square
		_square.DivMod(_square.Mul(_square, _square), modulus, square)
		exponent.Div(exponent, big.NewInt(2))
	}

	return result.String()
}
