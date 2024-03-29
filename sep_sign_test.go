package sep_sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIsAvailable(t *testing.T) {
	available, err := IsAvailable()
	require.NoError(t, err)
	t.Logf("IsAvailable=%v", available)
}

func TestGenerateAndSign(t *testing.T) {
	available, err := IsAvailable()
	require.NoError(t, err)
	if !available {
		t.SkipNow()
	}

	privateKey, publicKey, err := Generate(nil)
	require.NoError(t, err)

	data := make([]byte, 1024)
	_, err = rand.Read(data)
	require.NoError(t, err)

	sig, err := SignData(&SignOptions{PrivateKey: privateKey, Data: data})
	require.NoError(t, err)

	hash := sha256.Sum256(data)
	verified := ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), hash[:], sig)
	assert.True(t, verified, "Failed to verify signature!")
}

func TestGenerateAndSignWithBiometry(t *testing.T) {
	// Requires user-interaction, so disabled unless you comment this out
	//t.SkipNow()

	privateKey, publicKey, err := Generate(&GenerateOptions{
		RequireBiometry: true,
		RequireUnlocked: true,
	})
	require.NoError(t, err)

	data := make([]byte, 1024)
	_, err = rand.Read(data)
	require.NoError(t, err)

	sig, err := SignData(&SignOptions{AppName: "my app name", PrivateKey: privateKey, Data: data})
	require.NoError(t, err)

	hash := sha256.Sum256(data)
	verified := ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), hash[:], sig)
	assert.True(t, verified, "Failed to verify signature!")
}
