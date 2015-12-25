package vmprotect

var vmpBits int = 2048
var vmpModulus string = "7bJGXCsZBcavBdC3EC+vumdwd2NxzOSjnJvR4pkK1X2gdDCw3b2xOEHDWHiWyD4Y7fiUP31ka3EUiFN7hjd/xuIxADUPL9dVp/9Bfroe7jD6uyI4cy9/wrj75rHVmSPQpCUqDTEfLOU5WqCa9ZH/bU2UD5T9yCIergRAtplD1VvtnkeICpT8FeJfXEQdFWCU8Txv61t41ES+ozxafcTmR1UgC6J+g4si+fspehMmBZA8OFtKtjJd1r5Fr1DIuiplIQRaXhEpsDs095q7ArtMmP2AmS3TP5xgf3Qe/QdHSe4WJz8enbjfCr7FZlEjTrS7/mJwZ6ICAjXeS1KaYAM4GQ=="
var vmpPublic string = "AAEAAQ=="
var vmpProductCode string = "6rIktGJdjzY="

func compareByteSlice(a, b []byte) bool {

	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
