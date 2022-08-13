package argon2id

import "testing"

// TestArgon2ID verifies that Argon2ID is working correctly
func TestArgon2id(t *testing.T) {
	opts := Options{
		Memory:   64 * 1024,
		Time:     1,
		Threads:  2,
		KeySize:  32,
		SaltSize: 10,
	}

	var (
		password = []byte("password")
		hash, _  = Compute(opts, password)
		hash2, _ = Compute(opts, []byte("password2"))
	)

	if ok, _ := Verify(password, hash); !ok {
		t.Error("verify failed on valid password and hash")
	} else if ok, err := Verify(password, hash2); ok {
		t.Error("verify succeeded on password and invalid hash", err)
	}
}
