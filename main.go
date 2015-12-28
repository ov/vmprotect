package vmprotect

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

type License struct {
	Name, Email          string
	Expiration, MaxBuild time.Time
	HardwareId           []byte
	RunningTimeLimit     int
	UserData             []byte
	ProductCode          string
	Version              int
}

var exported_algorithm string = "RSA"
var exported_bits int = 2048
var exported_public string = "AAEAAQ=="
var exported_modulus string = "7bJGXCsZBcavBdC3EC+vumdwd2NxzOSjnJvR4pkK1X2gdDCw3b2xOEHDWHiWyD4Y7fiUP31ka3EUiFN7hjd/xuIxADUPL9dVp/9Bfroe7jD6uyI4cy9/wrj75rHVmSPQpCUqDTEfLOU5WqCa9ZH/bU2UD5T9yCIergRAtplD1VvtnkeICpT8FeJfXEQdFWCU8Txv61t41ES+ozxafcTmR1UgC6J+g4si+fspehMmBZA8OFtKtjJd1r5Fr1DIuiplIQRaXhEpsDs095q7ArtMmP2AmS3TP5xgf3Qe/QdHSe4WJz8enbjfCr7FZlEjTrS7/mJwZ6ICAjXeS1KaYAM4GQ==";
var exported_product_code string = "6rIktGJdjzY="

var test_serial string = "q6nn/37sjamWyZTsQPFsmHDkKf7tsDApRPO6Yv/D4bUdxs45qd2KkdKLwy+EcfqtCc1dqK8kfU0+VkAUgH+eKRYNBb/VJQ8igOVQxFqpgwXp0gXz3zE6mjropXfekVPZq+oP4YXg/0UfS1WrLXFoWASTbmqu8+WSWVNQgATgIZx/tONFwRXPXRQlRarTtLo8kl1w4qkKXWn7IYIEeakhpEI2W9Dd1lLZ25i8AfBMtoXe3/BJamtPgfEhpnN4YleXTd7uR6Ny34L+J6RKBf2r6l5/Dmgf4jEHosesS65EUa19ftgd8bW7Aj4Cu5cHdWO0C1kFtq2qKALurF4Qd01gHA=="

func base10Encode(str []byte) (string) {
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

		var _exp = new(big.Int)
		_exp.Set(exponent)
		_exp.Mod(_exp, big.NewInt(2))

		if _exp.Cmp(big.NewInt(0)) != 0 {
			var _result = result
			var mul_res = _result.Mul(_result, square)
			_result.DivMod(mul_res, modulus, result)
		}

		var _square = square
		_square.DivMod(_square.Mul(_square, _square), modulus, square)
		exponent.Div(exponent, big.NewInt(2))
	}

	return result.String()
}

func decodeSerial(strbin string) (string) {
	modulus, err := base64.StdEncoding.DecodeString(exported_modulus)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode exported_modulus: %v", exported_modulus)
	}

	public, err := base64.StdEncoding.DecodeString(exported_public)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode exported_public: %v", exported_public)
	}

	strbin = powmod(base10Encode([]byte(strbin)), base10Encode(public), base10Encode(modulus))
	return base10Decode(strbin)
}

func nextPos(strbin string, from int, count int) (int) {
	var size int = 0;

	for i := 0; i < count; i++ {
		_, _size := utf8.DecodeRuneInString(strbin[from + i:])
		size += _size
	}

	return size
}

func unpackSerial(strbin string) (*License, error) {
	var license = new (License)

	//skip front padding until \0
	var i int = 0
	for n := 0; n < utf8.RuneCountInString(strbin); n++ {
		ch, _ := utf8.DecodeRuneInString(strbin[n:])
		if int(ch) != 0 {
			i++
		} else {
			break
		}
	}

	sn_len := utf8.RuneCountInString(strbin)
	if i == sn_len {
		return nil, errors.New("Serial number parsing error (len)")
	}

	i += nextPos(strbin, i, 1)
	var start = i
	var end int = 0

	for i := start; i < utf8.RuneCountInString(strbin); {
		ch, size := utf8.DecodeRuneInString(strbin[i:])
		i += nextPos(strbin, i, size)

		if (ch == 1) {
			ch, size := utf8.DecodeRuneInString(strbin[i:])
			license.Version = int(ch)
			i += nextPos(strbin, i, size)
		} else if (ch == 2) {
			ch, size := utf8.DecodeRuneInString(strbin[i:])
			lenght := int(ch)
			i += nextPos(strbin, i, size)
			license.Name = strbin[i:i + lenght]
			i += lenght
		} else if (ch == 3) {
			ch, size := utf8.DecodeRuneInString(strbin[i:])
			lenght := int(ch)
			i += nextPos(strbin, i, size)
			license.Email = strbin[i:i + lenght]
			i += lenght
		} else if (ch == 4) {
			ch, size := utf8.DecodeRuneInString(strbin[i:])
			lenght := int(ch)
			i += nextPos(strbin, i, size)
			HardwareId, err := base64.StdEncoding.DecodeString(strbin[i:i + lenght])
			if err != nil {
				return nil, errors.New("Invalid serial number encoding")
			}
			license.HardwareId = HardwareId
			i += lenght
		} else if (ch == 5) {
			license.Expiration = time.Date(int(strbin[i + 2]) + int(strbin[i + 3]) * 256, time.Month(int(strbin[i + 1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += nextPos(strbin, i, 4)
		} else if (ch == 6) {
			license.RunningTimeLimit = int(strbin[i])
			i += nextPos(strbin, i, 1)
		} else if (ch == 7) {
			var productCode = make([]byte, 8)

			var rune_size = 0
			var rune_pos = 0
			for n, v := range strbin[i:] {
				if (rune_pos == 8) { break }
				productCode[rune_pos] = uint8(int32(v)&0xff)

				_, _size := utf8.DecodeRuneInString(strbin[i + n:])
				rune_size += _size
				rune_pos++
			}
			license.ProductCode = base64.StdEncoding.EncodeToString(productCode)
			i += rune_size
		} else if (ch == 8) {
			lenght := int(strbin[i])
			i += nextPos(strbin, i, 1)
			license.UserData = []byte(strbin[i:lenght])
			i += nextPos(strbin, i, lenght)
		} else if (ch == 9) {
			license.MaxBuild = time.Date(int(strbin[i + 2]) + int(strbin[i + 3]) * 256, time.Month(int(strbin[i + 1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += nextPos(strbin, i, 4)
		} else if (ch == 255) {
			end = i - 1;
			break;
		} else {
			return nil, errors.New("Serial number parsing error (chunk)")
		}
	}

	if end == 0 || sn_len - end < 4 {
		return nil, errors.New("Serial number CRC error")
	}

	var hash_arr = sha1.Sum([]byte(strbin[start:end - start]))
	var hash = string(hash_arr[:])
	
	var rev_hash string
	for i := 0; i < 4; i++ {
		rev_hash = hash[i:1] + rev_hash
	}

	var hash2 = strbin[end + 1: 4]
	
	if strings.Compare(rev_hash, hash2) != 0 {
		return nil, errors.New("Serial number CRC error")
	}
	
	return license, nil
}

func ParseLicense(serial, public, modulus, productCode string, bits int) (*License, error) {
	strings.Replace(serial, " ", "", -1)
	strings.Replace(serial, "\t", "", -1)
	strings.Replace(serial, "\n", "", -1)
	strings.Replace(serial, "\r", "", -1)
	
	_serial, err := base64.StdEncoding.DecodeString(serial)
	serial = string(_serial)

	if err != nil {
		return nil, errors.New("Invalid serial number encoding")
	} else if len(serial) < 240 || len(serial) > 260 {
		return nil, errors.New("Invalid length")
	} else {
		strbin := decodeSerial(serial);
		license, err := unpackSerial(strbin);

		if license.Version < 0 || len(license.ProductCode) == 0 {
			return nil, errors.New("Incomplete serial number")
		}

		if license.Version != 1 {
			return nil, errors.New("Unsupported version")
		}

		if strings.Compare(license.ProductCode, exported_product_code) != 0 {
			return nil, errors.New("Invalid product code")
		}

		return license, err
	}
}
