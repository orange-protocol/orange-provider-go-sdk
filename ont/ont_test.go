package ont

import (
	orange_provider_go_sdk "github.com/orange-protocol/orange-provider-go-sdk"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrangeProviderOntSdk_SignData(t *testing.T) {
	var psdk orange_provider_go_sdk.OrangeProviderSdk
	psdk, err := NewOrangeProviderOntSdk("./wallet.dat", "123456", "TESTNET")
	assert.Nil(t, err)

	s := "test data to sign"

	sig, err := psdk.SignData([]byte(s))
	assert.Nil(t, err)

	f, err := psdk.VerifySig(psdk.GetSelfDID(), []byte(s), sig)
	assert.Nil(t, err)
	assert.True(t, f)
}

func TestOrangeProviderOntSdk_EncryptDataWithDID(t *testing.T) {
	var psdk orange_provider_go_sdk.OrangeProviderSdk
	psdk, err := NewOrangeProviderOntSdk("./wallet.dat", "123456", "TESTNET")
	assert.Nil(t, err)

	s := "this is a secret string"

	encrypted, err := psdk.EncryptDataWithDID([]byte(s), psdk.GetSelfDID())
	assert.Nil(t, err)

	decrypted, err := psdk.DecryptData(encrypted)
	assert.Nil(t, err)
	assert.Equal(t, s, string(decrypted))
}
