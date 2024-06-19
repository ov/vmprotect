package vmprotect

import (
	"bytes"
	"crypto/rand"
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

func base10Encode(str []byte) string {
	var result = new(big.Int)
	for _, r := range str {
		result.Mul(result, big.NewInt(256))
		result.Add(result, big.NewInt(int64(r)))
	}

	return result.String()
}

func base10Decode(data *big.Int) []byte {
	var buffer bytes.Buffer

	for {
		if data.Cmp(big.NewInt(0)) <= 0 {
			break
		}
		var m = new(big.Int)
		data.DivMod(data, big.NewInt(256), m)

		var _buffer bytes.Buffer
		_buffer.WriteByte(uint8(m.Uint64() & 0xff))
		_buffer.Write(buffer.Bytes())
		buffer = _buffer
	}

	return buffer.Bytes()
}

func powmod(_base string, _exponent string, _modulus string) (*big.Int, error) {
	var base = new(big.Int)
	if _, succ := base.SetString(_base, 10); !succ {
		return nil, fmt.Errorf("error in powmod, can't convert _base: %v", _base)
	}

	var exponent = new(big.Int)
	if _, succ := exponent.SetString(_exponent, 10); !succ {
		return nil, fmt.Errorf("error in powmod, can't convert _exponent: %v", _exponent)
	}

	var modulus = new(big.Int)
	if _, succ := modulus.SetString(_modulus, 10); !succ {
		return nil, fmt.Errorf("error in powmod, can't convert _modulus: %v", _modulus)
	}

	zero := big.NewInt(0)

	if modulus.Cmp(zero) == 0 {
		return nil, errors.New("modulus is zero")
	}

	if exponent.Cmp(zero) == 0 {
		return nil, errors.New("exponent is zero")
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

	return result, nil
}

func decodeSerial(strbin, public, modulus string) ([]byte, error) {
	_modulus, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return nil, fmt.Errorf("error in decodeSerial, can't base64 decode modulus: %v", modulus)
	}

	_public, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return nil, fmt.Errorf("error in decodeSerial, can't base64 decode public: %v", public)
	}

	res, err := powmod(base10Encode([]byte(strbin)), base10Encode(_public), base10Encode(_modulus))
	if err != nil {
		return nil, err
	}

	return base10Decode(res), nil
}

func unpackSerial(strbin []byte) (*License, error) {
	var license = new(License)

	//skip front padding until \0
	i := 1
	for ; i < len(strbin); i++ {
		if int(strbin[i]) == 0 {
			break
		}
	}

	sn_len := len(strbin)
	if i == sn_len {
		return nil, errors.New("serial number parsing error (len)")
	}

	i++
	var start = i
	var end int = 0

	lenbin := len(strbin)

	for i := start; i < lenbin && end == 0; {
		ch := strbin[i]
		i++

		switch ch {

		case 1:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing version chunk, can't read byte %d out of %d", i, lenbin)
			}
			license.Version = int(strbin[i])
			i++

		case 2:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing name chunk, can't read byte %d out of %d", i, lenbin)
			}
			length := int(strbin[i])
			i++
			if i+length > lenbin {
				return nil, fmt.Errorf("error parsing name chunk. Start position = %d, length = %d, total data size = %d", i, length, len(strbin))
			}
			license.Name = string(strbin[i : i+length])
			i += length

		case 3:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing email chunk, can't read byte %d out of %d", i, lenbin)
			}
			length := int(strbin[i])
			i++
			if i+length > lenbin {
				return nil, fmt.Errorf("error parsing email chunk. Start position = %d, length = %d, total data size = %d", i, length, len(strbin))
			}
			license.Email = string(strbin[i : i+length])
			i += length

		case 4:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing hardware id chunk, can't read byte %d out of %d", i, lenbin)
			}
			length := int(strbin[i])
			i++
			if i+length > lenbin {
				return nil, fmt.Errorf("error parsing hardware id chunk. Start position = %d, length = %d, total data size = %d", i, length, len(strbin))
			}
			license.HardwareId = []byte(strbin[i : i+length])
			i += length

		case 5:
			if i+4 > lenbin {
				return nil, fmt.Errorf("error parsing expiration chunk. Start position = %d, length = 4, total data size = %d", i, len(strbin))
			}
			license.Expiration = time.Date(int(strbin[i+2])+int(strbin[i+3])*256, time.Month(int(strbin[i+1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4

		case 6:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing running time limit id chunk, can't read byte %d out of %d", i, lenbin)
			}
			license.RunningTimeLimit = int(strbin[i])
			i++

		case 7:
			if i+8 > lenbin {
				return nil, fmt.Errorf("error parsing product code chunk. Start position = %d, length = 8, total data size = %d", i, len(strbin))
			}
			license.ProductCode = base64.StdEncoding.EncodeToString([]byte(strbin[i : i+8]))
			i += 8

		case 8:
			if i >= lenbin {
				return nil, fmt.Errorf("error parsing user data chunk, can't read byte %d out of %d", i, lenbin)
			}
			length := int(strbin[i])
			i++
			if i+length > lenbin {
				return nil, fmt.Errorf("error parsing user data chunk. Start position = %d, length = %d, total data size = %d", i, length, len(strbin))
			}
			license.UserData = []byte(strbin[i : i+length])
			i += length

		case 9:
			if i+4 > lenbin {
				return nil, fmt.Errorf("error parsing max build chunk. Start position = %d, length = 4, total data size = %d", i, len(strbin))
			}
			license.MaxBuild = time.Date(int(strbin[i+2])+int(strbin[i+3])*256, time.Month(int(strbin[i+1])), int(strbin[i]), 0, 0, 0, 0, time.UTC)
			i += 4

		case 255:
			end = i - 1

		default:
			return nil, fmt.Errorf("unknown chunk %d at position %d+%d", ch, start, i-start)
		}
	}

	if end == 0 || sn_len-end < 4 {
		return nil, errors.New("serial number CRC error")
	}

	var sha1_hash_arr = sha1.Sum([]byte(strbin[start:end]))
	var rev_hash_arr = make([]byte, 4)
	for i := 0; i < 4; i++ {
		rev_hash_arr[3-i] = sha1_hash_arr[i]
	}

	var hash_arr = []byte(strbin[end+1 : end+1+4])

	if !bytes.Equal(rev_hash_arr, hash_arr) {
		return nil, errors.New("serial number CRC error")
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
		return nil, errors.New("invalid serial number encoding")
	}

	if len(_serial) < (bytes_len-6) || len(_serial) > (bytes_len+6) {
		return nil, errors.New("invalid length")
	}

	strbin, err := decodeSerial(string(_serial), public, modulus)
	if err != nil {
		return nil, err
	}

	license, err := unpackSerial(strbin)
	if err != nil {
		return nil, err
	}

	if license.Version < 0 || len(license.ProductCode) == 0 {
		return nil, errors.New("incomplete serial number")
	}

	if license.Version != 1 {
		return nil, errors.New("unsupported version")
	}

	if strings.Compare(license.ProductCode, productCode) != 0 {
		return nil, errors.New("invalid product code")
	}

	return license, err
}

func randomByte(min, max byte) (byte, error) {
	if max <= min {
		return 0, fmt.Errorf("invalid random number range: [%d, %d]", min, max)
	}

	dist := int64(max) - int64(min) + 1
	n, err := rand.Int(rand.Reader, big.NewInt(dist))
	if err != nil {
		return 0, err
	}

	if !n.IsInt64() {
		return 0, fmt.Errorf("the random number is too big to fit into int64: %q", n)
	}

	res64 := n.Int64() + int64(min)

	if res64 < 0 || res64 > 255 {
		return 0, fmt.Errorf("the random number does not fit into the byte: %q", res64)
	}

	return byte(res64), nil
}

func packSerial(l *License, bits int) ([]byte, error) {
	if l.Version != 1 {
		return nil, errors.New("unsupported version")
	}

	serial := []byte{0x01, 0x01} // version tag

	if l.Name != "" {
		length := len(l.Name)
		if length > 255 {
			return nil, errors.New("user name is too long")
		}

		serial = append(serial, 2)
		serial = append(serial, byte(length))
		serial = append(serial, l.Name...)
	}

	if l.Email != "" {
		length := len(l.Email)
		if length > 255 {
			return nil, errors.New("email is too long")
		}

		serial = append(serial, 3)
		serial = append(serial, byte(length))
		serial = append(serial, l.Email...)
	}

	if len(l.HardwareId) > 0 {
		length := len(l.HardwareId)

		serial = append(serial, 4)
		serial = append(serial, byte(length))
		serial = append(serial, l.HardwareId...)
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
			return nil, fmt.Errorf("product Code decoding error: %q", err)
		}

		if len(productCode) != 8 {
			return nil, fmt.Errorf("invalid Product Code, length is %d, not 8", len(productCode))
		}

		serial = append(serial, 7)
		serial = append(serial, productCode...)
	}

	if len(l.UserData) > 0 {
		length := len(l.UserData)
		if length > 255 {
			return nil, fmt.Errorf("user data is too long (%d bytes)", length)
		}

		serial = append(serial, 8)
		serial = append(serial, byte(length))
		serial = append(serial, l.UserData...)
	}

	if !l.MaxBuild.IsZero() {
		serial = append(serial, 9)
		serial = append(serial, byte(l.MaxBuild.Day()))
		serial = append(serial, byte(l.MaxBuild.Month()))
		serial = append(serial, byte(l.MaxBuild.Year()%256))
		serial = append(serial, byte(l.MaxBuild.Year()/256))
	}

	hash := sha1.Sum(serial)
	serial = append(serial, 255)
	for i := 0; i < 4; i++ {
		serial = append(serial, hash[3-i])
	}

	paddingFront := []byte{0x00, 0x02}

	paddingSize, err := randomByte(8, 16)
	if err != nil {
		return nil, fmt.Errorf("error getting random byte: %q", err)
	}

	for i := 0; i < int(paddingSize); i++ {
		rb, err := randomByte(1, 255)
		if err != nil {
			return nil, fmt.Errorf("error getting random byte: %q", err)
		}
		paddingFront = append(paddingFront, rb)
	}

	paddingFront = append(paddingFront, 0)

	contentSize := len(serial) + len(paddingFront)
	rest := bits/8 - contentSize
	if rest < 0 {
		return nil, fmt.Errorf("content is too big to fit the key: %d, maximum size is: %d", contentSize, bits/8)
	}

	paddingBack := []byte{}
	for i := 0; i < rest; i++ {
		rb, err := randomByte(0, 255)
		if err != nil {
			return nil, fmt.Errorf("error getting random byte: %q", err)
		}

		paddingBack = append(paddingBack, rb)
	}

	res := append(paddingFront, append(serial, paddingBack...)...)
	return res, nil
}

func MakeLicense(l *License, private, modulus string, bits int) (string, error) {
	packedSerial, err := packSerial(l, bits)
	if err != nil {
		return "", err
	}

	strRes, err := decodeSerial(string(packedSerial), private, modulus)
	if err != nil {
		return "", err
	}

	strPackedSerial := base64.StdEncoding.EncodeToString([]byte(strRes))

	return strPackedSerial, nil
}
