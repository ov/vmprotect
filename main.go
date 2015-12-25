package vmprotect

import (
	"errors"
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
