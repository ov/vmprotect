package vmprotect

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
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

func base10Encode(str []byte) string {
	var result = new(big.Int)
	for _, r := range str {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(r)))
	}

	return result.String()
}

func base10Decode(data *big.Int) string {
	var buffer bytes.Buffer

	var res string
	for {
		if data.Cmp(big.NewInt(0)) <= 0 {
			break
		}
		var m = new(big.Int)
		data.DivMod(data, big.NewInt(256), m)
		res = string(m.Uint64()&0xff) + res

		var _buffer bytes.Buffer
		_buffer.WriteByte(uint8(m.Uint64() & 0xff))
		_buffer.Write(buffer.Bytes())
		buffer = _buffer
	}

	return buffer.String()
}

func powmod(_base string, _exponent string, _modulus string) *big.Int {
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
	square.Mod(base, modulus)
	var result = big.NewInt(1)

	for {
		if exponent.Cmp(big.NewInt(0)) <= 0 {
			break
		}

		var _exp = new(big.Int)
		_exp.Mod(exponent, big.NewInt(2))

		if _exp.Cmp(big.NewInt(0)) != 0 {
			var _result = result
			_result.Mul(result, square)
			result.Mod(_result, modulus)
		}

		var _square = square
		square.Mod(_square.Mul(square, square), modulus)
		exponent.Div(exponent, big.NewInt(2))
	}

	return result
}

func decodeSerial(strbin, public, modulus string) string {
	_modulus, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode modulus: %v", modulus)
	}

	_public, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		fmt.Printf("Error in decodeSerial, can't base64 decode public: %v", public)
	}

	res := powmod(base10Encode([]byte(strbin)), base10Encode(_public), base10Encode(_modulus))
	return base10Decode(res)
}

func unpackSerial(strbin string) (*License, error) {
	var license = new(License)

	//skip front padding until \0
	var i int = 1
	for ; i < len(strbin); i++ {
		if int(strbin[i]) == 0 {
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
		ch := int(strbin[i])
		i++

		if ch == 1 {
			license.Version = int(strbin[i])
			i++
		} else if ch == 2 {
			lenght := int(strbin[i])
			i++
			license.Name = strbin[i : i+lenght]
			i += lenght
		} else if ch == 3 {
			lenght := int(strbin[i])
			i++
			license.Email = strbin[i : i+lenght]
			i += lenght
		} else if ch == 4 {
			lenght := int(strbin[i])
			i++
			license.HardwareId = []byte(strbin[i : i+8])
			i += lenght
		} else if ch == 5 {
			license.Expiration = time.Date(int(strbin[i+2])+int(strbin[i+3])*256, time.Month(int(strbin[i+1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if ch == 6 {
			license.RunningTimeLimit = int(strbin[i])
			i++
		} else if ch == 7 {
			license.ProductCode = base64.StdEncoding.EncodeToString([]byte(strbin[i : i+8]))
			i += 8
		} else if ch == 8 {
			lenght := int(strbin[i])
			i++
			license.UserData = []byte(strbin[i : i+lenght])
			i += lenght
		} else if ch == 9 {
			license.MaxBuild = time.Date(int(strbin[i+2])+int(strbin[i+3])*256, time.Month(int(strbin[i+1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4
		} else if ch == 255 {
			end = i - 1
			break
		} else {
			fmt.Println("ERROR", start, i, ch)
			return nil, errors.New("Serial number parsing error (chunk)")
		}
	}

	if end == 0 || sn_len-end < 4 {
		return nil, errors.New("Serial number CRC error")
	}

	var sha1_hash_arr = sha1.Sum([]byte(strbin[start:end]))
	var rev_hash_arr = make([]byte, 4)
	for i := 0; i < 4; i++ {
		rev_hash_arr[3-i] = sha1_hash_arr[i]
	}

	var hash_arr = []byte(strbin[end+1 : end+1+4])

	if bytes.Compare(rev_hash_arr, hash_arr) != 0 {
		return nil, errors.New("Serial number CRC error")
	}

	return license, nil
}

func filterSerial(serial string) string {
	alphabet := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
	var buffer bytes.Buffer
	serial_len := len(serial)
	for i := 0; i < serial_len; {
		ch := serial[i]
		// ASCII
		if ch < 0x80 {
			if bytes.IndexByte(alphabet, ch) != -1 {
				buffer.WriteByte(ch)
			}

			i++
			//UNICODE
		} else if ch < 0xC0 {
			i++
		} else if ch < 0xE0 {
			i += 2
		} else if ch < 0xF0 {
			i += 3
		} else if ch < 0xF8 {
			i += 4
		}
	}

	return buffer.String()
}

func ParseLicense(serial, public, modulus, productCode string, bits int) (*License, error) {
	bytes_len := bits / 8

	_serial, err := base64.StdEncoding.DecodeString(filterSerial(serial))
	if err != nil {
		return nil, errors.New("Invalid serial number encoding")
	} else if len(_serial) < (bytes_len-6) || len(_serial) > (bytes_len+6) {
		return nil, errors.New("Invalid length")
	} else {
		strbin := decodeSerial(string(_serial), public, modulus)
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

		if strings.Compare(license.ProductCode, productCode) != 0 {
			return nil, errors.New("Invalid product code")
		}

		return license, err
	}
}

func packSerial(l *License, bits int) ([]byte, error) {
	if l.Version != 1 {
		return []byte{}, errors.New("Unsupported version")
	}

	serial := make([]byte, 0)
	serial = append(serial, 1, 1)

	if l.Name != "" {
		nameLen := len(l.Name)
		if nameLen > 255 {
			return []byte{}, errors.New("User name is too long")
		}

		serial = append(serial, 2)
		serial = append(serial, byte(nameLen))
		for i := 0; i < nameLen; i++ {
			serial = append(serial, l.Name[i])
		}
	}

	if l.Email != "" {
		emailLen := len(l.Email)
		if emailLen > 255 {
			return []byte{}, errors.New("E-Mail is too long")
		}

		serial = append(serial, 3)
		serial = append(serial, byte(emailLen))
		for i := 0; i < emailLen; i++ {
			serial = append(serial, l.Email[i])
		}
	}

	if len(l.HardwareId) > 0 {
		serial = append(serial, 4)
		hdwIDLen := len(l.HardwareId)
		serial = append(serial, byte(hdwIDLen))
		for i := 0; i < hdwIDLen; i++ {
			serial = append(serial, l.HardwareId[i])
		}
	}

	if !l.Expiration.IsZero() {
		serial = append(serial, 5)
		serial = append(serial, byte(l.Expiration.Day()))
		serial = append(serial, byte(l.Expiration.Month()))
		serial = append(serial, byte(l.Expiration.Year()%256))
		serial = append(serial, byte(l.Expiration.Year()/256))
	}

	if l.RunningTimeLimit > 0 {
		serial = append(serial, 6)
		serial = append(serial, byte(l.RunningTimeLimit))
	}

	if l.ProductCode != "" {
		productCode, err := base64.StdEncoding.DecodeString(l.ProductCode)
		if err != nil {
			return []byte{}, fmt.Errorf("Invalid ProductCode decoding: %q", err)
		}

		serial = append(serial, 7)
		for i := 0; i < 8; i++ {
			serial = append(serial, productCode[i])
		}
	}

	if len(l.UserData) > 0 {
		userDataLen := len(l.UserData)
		if len(l.UserData) > 255 {
			return []byte{}, errors.New("User data is too long")
		}

		serial = append(serial, 8)
		serial = append(serial, byte(userDataLen))
		for i := 0; i < userDataLen; i++ {
			serial = append(serial, l.UserData[i])
		}
	}

	if !l.MaxBuild.IsZero() {
		serial = append(serial, 9)
		serial = append(serial, byte(l.MaxBuild.Day()))
		serial = append(serial, byte(l.MaxBuild.Month()))
		serial = append(serial, byte(l.MaxBuild.Year()%256))
		serial = append(serial, byte(l.MaxBuild.Year()/256))
	}

	var sha1HashArr = sha1.Sum(serial)
	serial = append(serial, 255)
	for i := 0; i < 4; i++ {
		serial = append(serial, sha1HashArr[3-i])
	}

	paddingFront := []byte{0, 2}
	randSize := 8 + rand.Intn(9) // from 8 to 16 inclusive
	for i := 0; i < randSize; i++ {
		paddingFront = append(paddingFront, byte(1+rand.Intn(256)))
	}
	paddingFront = append(paddingFront, 0)

	contentSize := len(serial) + len(paddingFront)
	rest := bits/8 - contentSize
	if rest < 0 {
		return []byte{}, fmt.Errorf("Content is too big to fit in key: %d, maximal allowed is: %d", contentSize, bits/8)
	}

	paddingBack := make([]byte, 0)
	for i := 0; i < rest; i++ {
		paddingBack = append(paddingFront, byte(rand.Intn(256)))
	}

	paddingFront = append(paddingFront, serial...)
	serial = append(paddingFront, paddingBack...)

	return serial, nil
}

func MakeLicense(l *License, private, modulus string, bits int) (string, error) {
	packedSerial, err := packSerial(l, bits)
	if err != nil {
		return "", err
	}

	/*
		_modulus, err := base64.StdEncoding.DecodeString(modulus)
		if err != nil {
			return "", errors.New("Invalid modulus")
		}

		_private, err := base64.StdEncoding.DecodeString(private)
		if err != nil {
			return "", errors.New("Invalid private key")
		}

		modulus = base10Encode(_modulus)
		private = base10Encode(_private)
		strPackedSerial := base10Encode(packedSerial)

		res := powmod(strPackedSerial, private, modulus)
		strRes := base10Decode(res)
	*/

	strRes := decodeSerial(string(packedSerial), private, modulus)
	strPackedSerial := base64.StdEncoding.EncodeToString([]byte(strRes))

	return strPackedSerial, nil
}
