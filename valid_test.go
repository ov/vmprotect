﻿package vmprotect

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNameEmailAndUserData(t *testing.T) {
	serial := "b2HUC5SA0qqHSmJHAJe+pM9Q5sey+iqCqkW3e0cK8R3kSxlGsFrVzVJ/OZ5etJ8DeDHCKBbmismtwd3I9uzJwitfR/NJJ93u/n/5J0RFDAkklyJ+A23mEDtdwP/w/LS97jvFMfXwX0SMBtQ28948iraiu7VeruU9SZcUerlPLtXj4AKoUOzfciWYJ9xDMA+daJOFioMd7zNZ2AW7bz8PB9+X5Vrtg6fg7QPaJuuXBqkQyxKaoBm/YCcVNBST0LpP0upDV/FDAhHXJL6hjvt55RE6vdHt75othC9diQAIxREN8JhrGkZnOGEypwB5wBCGYeD43bc8s+AM3P7AtUlxxg=="
	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)

	require.Nil(t, err, "The serial number is valid, it should be parsed well")
	require.NotNil(t, lic, "The license information must be returned")
	require.Equal(t, lic.Name, "Test Name", "Invalid name")
	require.Equal(t, lic.Email, "test@email.com", "Invalid email")
	require.Equal(t, lic.UserData, []byte{1, 2, 3}, "Invalid user data")
	require.Zero(t, lic.Expiration, "Expiration date must be zero")
	require.Zero(t, lic.MaxBuild, "Max build date must be zero")
	require.Zero(t, lic.RunningTimeLimit, 47, "Running time limit must be zero")
	require.Nil(t, lic.HardwareId, "Hardware ID must be empty")
}

func TestNameEmailAndDates(t *testing.T) {
	serial := "tCSbx9HaC2k4m1X+gfJp3W9g8G86yD3NveCZ+a8TIS08giioeH7xWzuKekcuBXcBp46FpwNi/JpCyyAIPbv/O5twD+acrmINsnq10uBbgIAw8UXIc8RrfIfnQUtbvXDyXpky7NF68BcSBuLSrANqeK2fA07BnE07Nit8BclAIknzYpQp/fp7oPOiil3PIwqh+it3Y060UBEMggnf9GIGhfm+vFkgp90eCFaGJA3l/FFXkQ6S76kq4d+32H8Gv2O1FFol17sgOmWEU1t9VTHXHA/7l+H2LssJyMeEHQ70yWekjiznX270t4jML6iYTFzqk4d6nZl4KO4xTJBpd7hX/w=="
	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)

	require.Nil(t, err, "The serial number is valid, it should be parsed well")
	require.NotNil(t, lic, "The license information must be returned")
	require.Equal(t, lic.Name, "Иван Петров", "Invalid name")
	require.Equal(t, lic.Email, "иван@петров.рф", "Invalid email")
	require.Nil(t, lic.UserData, "User data must be nil")
	require.Equal(t, lic.Expiration, time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC), "Expiration date must be 24/12/2015")
	require.Equal(t, lic.MaxBuild, time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC), "Max build date must be 25/11/2014")
	require.Equal(t, lic.RunningTimeLimit, 47, "Running time limit must be 47")
	require.Nil(t, lic.HardwareId, "Hardware ID must be empty")
}

func TestNameEmailAndHardwareId(t *testing.T) {
	serial := "q6nn/37sjamWyZTsQPFsmHDkKf7tsDApRPO6Yv/D4bUdxs45qd2KkdKLwy+EcfqtCc1dqK8kfU0+VkAUgH+eKRYNBb/VJQ8igOVQxFqpgwXp0gXz3zE6mjropXfekVPZq+oP4YXg/0UfS1WrLXFoWASTbmqu8+WSWVNQgATgIZx/tONFwRXPXRQlRarTtLo8kl1w4qkKXWn7IYIEeakhpEI2W9Dd1lLZ25i8AfBMtoXe3/BJamtPgfEhpnN4YleXTd7uR6Ny34L+J6RKBf2r6l5/Dmgf4jEHosesS65EUa19ftgd8bW7Aj4Cu5cHdWO0C1kFtq2qKALurF4Qd01gHA=="
	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)

	require.Nil(t, err, "The serial number is valid, it should be parsed well")
	require.NotNil(t, lic, "The license information must be returned")
	require.Equal(t, lic.Name, "John Doe", "Invalid name")
	require.Equal(t, lic.Email, "john@doe.com", "Invalid email")
	require.Nil(t, lic.UserData, "User data must be nil")
	require.Zero(t, lic.Expiration, "Expiration date must be zero")
	require.Zero(t, lic.MaxBuild, "Max build date must be zero")
	require.Zero(t, lic.RunningTimeLimit, "Running time limit must be zero")
	require.Equal(t, lic.HardwareId, []byte{'0', '0', '1', '1', '2', '2', '3', '3'}, "Hardware ID must be defined")
}

func TestNameEmailAndWhitespacesAndUnsupportedCharacters(t *testing.T) {
	serial := "b2HUC5SA0qqHSmJHAJe+pM9Q5sey+iqCqkW3e0cK8     R3kSxlGsFrVzVJ/OZ5etJ8DeDHCKBbmismt\n\nwd3I9uzJwitfR/NJJ93u/n/5J0RFDAkklyJ+A23mEDtdwP\r\n/w/LS97jvFMfXwX0\t\t\tSMBtQ28948iraiu7VeruU9SZcUerlPLtXj4[AKoUOzfciWYJ9xDMA+d]aJOFioMd7zNZ2AW7bz8PB9+X5Vrtg6fg7QPaJuuX-------BqkQyxKaoBm/YCcVNBST0LpP0upDV/FDAhHXJL6hjvt55RE6vdHt75othC9diQAIxREN8*****************JhrGkZnOGEypwB5wBCGYeD43bc8s+AM3приветP7AtUlxxg=="
	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)

	require.Nil(t, err, "The serial number is valid, it should be parsed well")
	require.NotNil(t, lic, "The license information must be returned")
	require.Equal(t, lic.Name, "Test Name", "Invalid name")
	require.Equal(t, lic.Email, "test@email.com", "Invalid email")
	require.Equal(t, lic.UserData, []byte{1, 2, 3}, "Invalid user data")
	require.Zero(t, lic.Expiration, "Expiration date must be zero")
	require.Zero(t, lic.MaxBuild, "Max build date must be zero")
	require.Zero(t, lic.RunningTimeLimit, "Running time limit must be zero")
	require.Nil(t, lic.HardwareId, "Hardware ID must be empty")
}
func TestMakeLicense(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="

	l := new(License)
	l.Name = "John Doe"
	l.Email = "john@doe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	serial, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.Nil(t, err, "The serial number is valid, it should be parsed well")

	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)
	require.Nil(t, err)

	require.Equal(t, lic.Name, l.Name, "Invalid name")
	require.Equal(t, lic.Email, l.Email, "Invalid email")
	require.NotZero(t, lic.Expiration, "Expiration date must not be zero")
	require.NotZero(t, lic.MaxBuild, "Max build date must not be zero")
	require.Equal(t, lic.RunningTimeLimit, l.RunningTimeLimit, "Running time limit must be 47")
	require.Equal(t, lic.HardwareId, l.HardwareId, "Hardware ID must be defined")
	require.Equal(t, lic.ProductCode, vmpProductCode, "Wrong pruduct code")
	require.NotNil(t, lic.UserData, "User data must not be nil")
	require.Equal(t, lic.Version, l.Version, "Version must be 1")
}
func TestMakeLicenseLongName(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe"
	l.Email = "john@doe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	serial, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.Nil(t, err, "The serial number is valid, it should be parsed well")

	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)
	require.Nil(t, err)

	require.Equal(t, lic.Name, l.Name, "Invalid name")
	require.Equal(t, lic.Email, l.Email, "Invalid email")
	require.NotZero(t, lic.Expiration, "Expiration date must not be zero")
	require.NotZero(t, lic.MaxBuild, "Max build date must not be zero")
	require.Equal(t, lic.RunningTimeLimit, l.RunningTimeLimit, "Running time limit must be 47")
	require.Equal(t, lic.HardwareId, l.HardwareId, "Hardware ID must be defined")
	require.Equal(t, lic.ProductCode, vmpProductCode, "Wrong pruduct code")
	require.NotNil(t, lic.UserData, "User data must not be nil")
	require.Equal(t, lic.Version, l.Version, "Version must be 1")
}

func TestMakeLicenseTooLongName(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe John Doe"
	l.Email = "john@doe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	_, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "content is too big to fit the key")
}
func TestMakeLicenseLongEmail(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John Doe"
	l.Email = "johnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohn@doedoedoedoedoedoedoedoedoe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	serial, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.Nil(t, err, "The serial number is valid, it should be parsed well")

	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)
	require.Nil(t, err)

	require.Equal(t, lic.Name, l.Name, "Invalid name")
	require.Equal(t, lic.Email, l.Email, "Invalid email")
	require.NotZero(t, lic.Expiration, "Expiration date must not be zero")
	require.NotZero(t, lic.MaxBuild, "Max build date must not be zero")
	require.Equal(t, lic.RunningTimeLimit, l.RunningTimeLimit, "Running time limit must be 47")
	require.Equal(t, lic.HardwareId, l.HardwareId, "Hardware ID must be defined")
	require.Equal(t, lic.ProductCode, vmpProductCode, "Wrong pruduct code")
	require.NotNil(t, lic.UserData, "User data must not be nil")
	require.Equal(t, lic.Version, l.Version, "Version must be 1")
}
func TestMakeLicenseTooLongEmail(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John Doe"
	l.Email = "johnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohnjohn@doedoedoedoedoedoedoedoedoe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	_, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "content is too big to fit the key")
}

func TestMakeLicenseUnicodeInNameAndEmail(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John ぁあぃいぅうぇえ Doe"
	l.Email = "johnぁあぃいぅうぇえ@doeぁあぃいぅうぇえdoe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.ProductCode = vmpProductCode
	l.UserData = []byte("Test User Data")
	l.Version = 1

	serial, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.Nil(t, err, "The serial number is valid, it should be parsed well")

	lic, err := ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)
	require.Nil(t, err)

	require.Equal(t, lic.Name, l.Name, "Invalid name")
	require.Equal(t, lic.Email, l.Email, "Invalid email")
	require.NotZero(t, lic.Expiration, "Expiration date must not be zero")
	require.NotZero(t, lic.MaxBuild, "Max build date must not be zero")
	require.Equal(t, lic.RunningTimeLimit, l.RunningTimeLimit, "Running time limit must be 47")
	require.Equal(t, lic.HardwareId, l.HardwareId, "Hardware ID must be defined")
	require.Equal(t, lic.ProductCode, vmpProductCode, "Wrong pruduct code")
	require.NotNil(t, lic.UserData, "User data must not be nil")
	require.Equal(t, lic.Version, l.Version, "Version must be 1")
}

func TestMakeLicenseWithoutProductKey(t *testing.T) {
	private := "BM8O4xm4nIAt5YxYzcYnNBpYYUP05xAnmrkgzIir2lCbtMoQ4/WM3q5e6zzqUQQHmVXmeufYpp9Pqufkd31LM5z7II3SQDWnLRpKCwwtKMS7J9rMAVGQUEJRj1Pg9kOOGqoJUSHBp5T+HW4jIG17GU0g3hVVso01KXBa1k7gu1HiL/NbNZK8hdGz45cRp+J3PhJRg3o8Lwm8PHfIi486rXrLmbi0J9Xw5lH+VItebpRP0OqjDSv4/6uaNMZnztnGBPptBlXfQnT+Xm7ocI3Bqgv1jan1fIwn9skla5H7m1prpSK3KL9tyuACKM+isNfyrgCm5bYoKHn4mCqB08INsQ=="
	l := new(License)
	l.Name = "John Doe"
	l.Email = "john@doe.com"
	l.Expiration = time.Date(2015, 12, 24, 0, 0, 0, 0, time.UTC)
	l.MaxBuild = time.Date(2014, 11, 25, 0, 0, 0, 0, time.UTC)
	l.RunningTimeLimit = 47
	l.HardwareId = []byte{'0', '0', '1', '1', '2', '2', '3', '3'}
	l.UserData = []byte("Test User Data")
	l.Version = 1

	serial, err := MakeLicense(l, private, vmpModulus, vmpBits)
	require.Nil(t, err, "The serial number is valid, it should be parsed well")

	_, err = ParseLicense(serial, vmpPublic, vmpModulus, vmpProductCode, vmpBits)
	require.NotNil(t, err)
	require.Equal(t, "incomplete serial number", err.Error())
}
