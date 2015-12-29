package vmprotect

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
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
var exported_product_code string = "6rIktGJdjzY="
var exported_modulus string = "7bJGXCsZBcavBdC3EC+vumdwd2NxzOSjnJvR4pkK1X2gdDCw3b2xOEHDWHiWyD4Y7fiUP31ka3EUiFN7hjd/xuIxADUPL9dVp/9Bfroe7jD6uyI4cy9/wrj75rHVmSPQpCUqDTEfLOU5WqCa9ZH/bU2UD5T9yCIergRAtplD1VvtnkeICpT8FeJfXEQdFWCU8Txv61t41ES+ozxafcTmR1UgC6J+g4si+fspehMmBZA8OFtKtjJd1r5Fr1DIuiplIQRaXhEpsDs095q7ArtMmP2AmS3TP5xgf3Qe/QdHSe4WJz8enbjfCr7FZlEjTrS7/mJwZ6ICAjXeS1KaYAM4GQ=="

//var test_serial string = "q6nn/37sjamWyZTsQPFsmHDkKf7tsDApRPO6Yv/D4bUdxs45qd2KkdKLwy+EcfqtCc1dqK8kfU0+VkAUgH+eKRYNBb/VJQ8igOVQxFqpgwXp0gXz3zE6mjropXfekVPZq+oP4YXg/0UfS1WrLXFoWASTbmqu8+WSWVNQgATgIZx/tONFwRXPXRQlRarTtLo8kl1w4qkKXWn7IYIEeakhpEI2W9Dd1lLZ25i8AfBMtoXe3/BJamtPgfEhpnN4YleXTd7uR6Ny34L+J6RKBf2r6l5/Dmgf4jEHosesS65EUa19ftgd8bW7Aj4Cu5cHdWO0C1kFtq2qKALurF4Qd01gHA=="
//var test_serial string = "b2HUC5SA0qqHSmJHAJe+pM9Q5sey+iqCqkW3e0cK8R3kSxlGsFrVzVJ/OZ5etJ8DeDHCKBbmismtwd3I9uzJwitfR/NJJ93u/n/5J0RFDAkklyJ+A23mEDtdwP/w/LS97jvFMfXwX0SMBtQ28948iraiu7VeruU9SZcUerlPLtXj4AKoUOzfciWYJ9xDMA+daJOFioMd7zNZ2AW7bz8PB9+X5Vrtg6fg7QPaJuuXBqkQyxKaoBm/YCcVNBST0LpP0upDV/FDAhHXJL6hjvt55RE6vdHt75othC9diQAIxREN8JhrGkZnOGEypwB5wBCGYeD43bc8s+AM3P7AtUlxxg=="
//var test_serial string = "tCSbx9HaC2k4m1X+gfJp3W9g8G86yD3NveCZ+a8TIS08giioeH7xWzuKekcuBXcBp46FpwNi/JpCyyAIPbv/O5twD+acrmINsnq10uBbgIAw8UXIc8RrfIfnQUtbvXDyXpky7NF68BcSBuLSrANqeK2fA07BnE07Nit8BclAIknzYpQp/fp7oPOiil3PIwqh+it3Y060UBEMggnf9GIGhfm+vFkgp90eCFaGJA3l/FFXkQ6S76kq4d+32H8Gv2O1FFol17sgOmWEU1t9VTHXHA/7l+H2LssJyMeEHQ70yWekjiznX270t4jML6iYTFzqk4d6nZl4KO4xTJBpd7hX/w=="
//var test_serial string = "b2HUC5SA0qqHSmJHAJe+pM9Q5sey+iqCqkW3e0cK8R3kSxlGsFrVzVJ/OZ5etJ8DeDHCKBbmismtwd3I9uzJwitfR/NJJ93u/n/5J0RFDAkklyJ+A23mEDtdwP/w/LS97jvFMfXwX0SMBtQ28948iraiu7VeruU9SZcUerlPLtXj4AKoUOzfciWYJ9xDMA+daJOFioMd7zNZ2AW7bz8PB9+X5Vrtg6fg7QPaJuuXBqkQyxKaoBm/YCcVNBST0LpP0upDV/FDAhHXJL6hjvt55RE6vdHt75othC9diQAIxREN8JhrGkZnOGEypwB5wBCGYeD43bc8s+AM3P7AtUlxxg=="
var test_serial string = "q6nn/37sjamWyZTsQPFsmHDkKf7tsDApRPO6Yv/D4bUdxs45qd2KkdKLwy+EcfqtCc1dqK8kfU0+VkAUgH+eKRYNBb/VJQ8igOVQxFqpgwXp0gXz3zE6mjropXfekVPZq+oP4YXg/0UfS1WrLXFoWASTbmqu8+WSWVNQgATgIZx/tONFwRXPXRQlRarTtLo8kl1w4qkKXWn7IYIEeakhpEI2W9Dd1lLZ25i8AfBMtoXe3/BJamtPgfEhpnN4YleXTd7uR6Ny34L+J6RKBf2r6l5/Dmgf4jEHosesS65EUa19ftgd8bW7Aj4Cu5cHdWO0C1kFtq2qKALurF4Qd01gHA=="

func base10Encode(str []byte) (string) {
	var result = big.NewInt(0)
	for _, r := range str {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(r)))
	}

	return result.String()
}

func base10Decode(data *big.Int) (string) {
	var buffer bytes.Buffer

	var res string
	for {
		if data.Cmp(big.NewInt(0)) <= 0 { break }
		var m = new(big.Int)
		data.DivMod(data, big.NewInt(256), m)
		res =  string(m.Uint64() & 0xff) + res

		var _buffer bytes.Buffer
		_buffer.WriteByte(uint8(m.Uint64() & 0xff))
		_buffer.Write(buffer.Bytes())
		buffer = _buffer
	}

	return buffer.String()
}

func powmod(_base string, _exponent string, _modulus string) (*big.Int) {
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

	return result
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

	res := powmod(base10Encode([]byte(strbin)), base10Encode(public), base10Encode(modulus))
	return base10Decode(res)
}

func unpackSerial(strbin string) (*License, error) {
	var license = new (License)

	//skip front padding until \0
	var i int = 1
	for ; i < len(strbin); i++ {
		arr := []byte(strbin[i:i+1])
		if int(arr[0]) == 0 {
			break
		}
	}

	sn_len := len(strbin)
	if i == sn_len {
		return nil, errors.New("Serial number parsing error (len)")
	}

	i++
	var start = i
	var end int = 0

	for i := start; i < len(strbin); {
		_b := []byte(strbin[i:i+1])
		ch := int(_b[0])
		i++

		if (ch == 1) {
			arr := []byte(strbin[i:i+1])
			license.Version = int(arr[0])
			i++
		} else if (ch == 2) {
			arr := []byte(strbin[i:i+1])
			lenght := int(arr[0])
			i++
			license.Name = strbin[i:i + lenght]
			i += lenght
		} else if (ch == 3) {
			arr := []byte(strbin[i:i+1])
			lenght := int(arr[0])
			i++
			license.Email = strbin[i:i + lenght]
			i += lenght
		} else if (ch == 4) {
			arr := []byte(strbin[i:i+1])
			lenght := int(arr[0])
			i++
			license.HardwareId = []byte(strbin[i:i+8])
			i += lenght
		} else if (ch == 5) {
			license.Expiration = time.Date(int(strbin[i + 2]) + int(strbin[i + 3]) * 256, time.Month(int(strbin[i + 1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if (ch == 6) {
			arr := []byte(strbin[i:i+1])
			license.RunningTimeLimit = int(arr[0])
			i++
		} else if (ch == 7) {
			arr := []byte(strbin[i:i+8])
			license.ProductCode = base64.StdEncoding.EncodeToString(arr)
			i += 8
		} else if (ch == 8) {
			arr := []byte(strbin[i:i+1])
			lenght := int(arr[0])
			i++
			license.UserData = []byte(strbin[i:i+lenght])
			i += lenght
		} else if (ch == 9) {
			license.MaxBuild = time.Date(int(strbin[i + 2]) + int(strbin[i + 3]) * 256, time.Month(int(strbin[i + 1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if (ch == 255) {
			end = i - 1
			break
		} else {
			fmt.Println("ERROR", start, i, ch);
			return nil, errors.New("Serial number parsing error (chunk)")
		}
	}

	if end == 0 || sn_len - end < 4 {
		return nil, errors.New("Serial number CRC error")
	}

	var sha1_hash_arr = sha1.Sum([]byte(strbin[start:end]))
	var rev_hash_arr = make([]byte, 4)
	for i := 0; i < 4; i++ {
		rev_hash_arr[3 - i] = sha1_hash_arr[i]
	}

	var hash_arr = []byte(strbin[end + 1: end + 1 + 4])

	if bytes.Compare(rev_hash_arr, hash_arr) != 0 {
		return nil, errors.New("Serial number CRC error")
	}

	return license, nil
}

func ParseLicense(serial, public, modulus, productCode string, bits int) (*License, error) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	filtered_serial := ""
	for _, c := range serial {
		s := string(c)
		if strings.Index(alphabet, s) != -1 {
			filtered_serial += s
		}
	}
	
	_serial, err := base64.StdEncoding.DecodeString(filtered_serial)
	if err != nil {
		return nil, errors.New("Invalid serial number encoding")
	} else if len(_serial) < 240 || len(_serial) > 260 {
		return nil, errors.New("Invalid length")
	} else {
		strbin := decodeSerial(string(_serial))
		license, err := unpackSerial(strbin)
		
		if err != nil {
			return nil, err
		}

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

func main() {
	license, err := ParseLicense(test_serial, exported_public, exported_modulus, exported_product_code, exported_bits)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Println("Version", license.Version)
		fmt.Println("Name", license.Name)
		fmt.Println("Email", license.Email)
		fmt.Println("HardwareId", license.HardwareId)
		fmt.Println("ProductCode", license.ProductCode)
		fmt.Println("UserData", license.UserData)
		fmt.Println("Expiration", license.Expiration)
		fmt.Println("MaxBuild", license.MaxBuild)
		fmt.Println("RunningTimeLimit", license.RunningTimeLimit)
	}
}
