package vmprotect

import (
	"encoding/base64"
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

val exported_algorithm string = "RSA"
var exported_bits int = 2048
var exported_public string = "AAEAAQ=="
var exported_modulus string = "7bJGXCsZBcavBdC3EC+vumdwd2NxzOSjnJvR4pkK1X2gdDCw3b2xOEHDWHiWyD4Y7fiUP31ka3EUiFN7hjd/xuIxADUPL9dVp/9Bfroe7jD6uyI4cy9/wrj75rHVmSPQpCUqDTEfLOU5WqCa9ZH/bU2UD5T9yCIergRAtplD1VvtnkeICpT8FeJfXEQdFWCU8Txv61t41ES+ozxafcTmR1UgC6J+g4si+fspehMmBZA8OFtKtjJd1r5Fr1DIuiplIQRaXhEpsDs095q7ArtMmP2AmS3TP5xgf3Qe/QdHSe4WJz8enbjfCr7FZlEjTrS7/mJwZ6ICAjXeS1KaYAM4GQ==";
var exported_product_code string = "6rIktGJdjzY="

var test_serial string = "q6nn/37sjamWyZTsQPFsmHDkKf7tsDApRPO6Yv/D4bUdxs45qd2KkdKLwy+EcfqtCc1dqK8kfU0+VkAUgH+eKRYNBb/VJQ8igOVQxFqpgwXp0gXz3zE6mjropXfekVPZq+oP4YXg/0UfS1WrLXFoWASTbmqu8+WSWVNQgATgIZx/tONFwRXPXRQlRarTtLo8kl1w4qkKXWn7IYIEeakhpEI2W9Dd1lLZ25i8AfBMtoXe3/BJamtPgfEhpnN4YleXTd7uR6Ny34L+J6RKBf2r6l5/Dmgf4jEHosesS65EUa19ftgd8bW7Aj4Cu5cHdWO0C1kFtq2qKALurF4Qd01gHA=="

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

func decodeSerial(binary string) (string) {
	modulus, err := base64.StdEncoding.DecodeString(exported_modulus)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode exported_modulus: %v", exported_modulus)
	}

	public, err := base64.StdEncoding.DecodeString(exported_public)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode exported_public: %v", exported_public)
	}

	binary = base10Encode(binary);
	binary = powmod(binary, base10Encode(string(public)), base10Encode(string(modulus)));
	return base10Decode(binary);
}
