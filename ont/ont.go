package ont

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	ontology_go_sdk "github.com/ontio/ontology-go-sdk"
)

type DidPubkey struct {
	Id           string      `json:"id"`
	Type         string      `json:"type"`
	Controller   interface{} `json:"controller"`
	PublicKeyHex string      `json:"publicKeyHex"`
}

type OrangeProviderOntSdk struct {
	account *ontology_go_sdk.Account
	ontsdk  *ontology_go_sdk.OntologySdk
}

func NewOrangeProviderOntSdk(walletPath string, pwd string, network string) (*OrangeProviderOntSdk, error) {
	url := "http://polaris2.ont.io:20336"
	if network == "MAINNET" {
		url = "http://dappnode2.ont.io:20336"
	}

	ontSdk := ontology_go_sdk.NewOntologySdk()
	ontSdk.NewRpcClient().SetAddress(url)
	wallet, err := ontology_go_sdk.OpenWallet(walletPath)
	if err != nil {
		return nil, err
	}
	account, err := wallet.GetDefaultAccount([]byte(pwd))
	if err != nil {
		return nil, err
	}

	return &OrangeProviderOntSdk{
		account: account,
		ontsdk:  ontSdk,
	}, nil
}

func (s *OrangeProviderOntSdk) SignData(data []byte) ([]byte, error) {
	return s.account.Sign(data)
}

func (s *OrangeProviderOntSdk) GetSelfDID() string {
	return fmt.Sprintf("did:ont:%s", s.account.Address.ToBase58())
}

func (s *OrangeProviderOntSdk) getDIDPubkey(did string) ([]byte, error) {
	if s.ontsdk.Native == nil || s.ontsdk.Native.OntId == nil {
		return nil, fmt.Errorf("sdk is empty")
	}

	pubKey, err := s.ontsdk.Native.OntId.GetPublicKeysJson(did)
	if err != nil {
		return nil, err
	}
	var pks []DidPubkey
	err = json.Unmarshal(pubKey, &pks)
	if err != nil {
		return nil, err
	}
	if len(pks) == 0 {
		return nil, fmt.Errorf("pubkey is empty")
	}
	return hex.DecodeString(pks[0].PublicKeyHex)
}

func (s *OrangeProviderOntSdk) DecryptData(msg []byte) ([]byte, error) {
	ecdsaPrivkey, err := PrivateKeyToEcdsaPrivkey(keypair.SerializePrivateKey(s.account.PrivateKey))
	if err != nil {
		return nil, err
	}

	return DecryptMsg(ecdsaPrivkey, msg)
}

func (s *OrangeProviderOntSdk) EncryptDataWithDID(data []byte, did string) ([]byte, error) {

	pubkey, err := s.getDIDPubkey(did)
	if err != nil {
		return nil, fmt.Errorf("get pubkey from did:%s failed", did)
	}
	return EncryptWithDIDPubkey(data, pubkey)
}

func (s *OrangeProviderOntSdk) VerifySig(did string, msg []byte, sigbytes []byte) (bool, error) {
	pkbytes, err := s.getDIDPubkey(did)
	if err != nil {
		return false, err
	}

	pk, err := keypair.DeserializePublicKey(pkbytes)
	if err != nil {
		return false, err
	}
	sig, err := signature.Deserialize(sigbytes)
	if err != nil {
		return false, err
	}
	return signature.Verify(pk, msg, sig), err
}

func EncryptWithDIDPubkey(msg []byte, didpubkey []byte) ([]byte, error) {
	ecdsaPubkey, err := UnmarshalPubkey(didpubkey)
	if err != nil {
		return nil, err
	}
	eciesPubkey := ecies.ImportECDSAPublic(ecdsaPubkey)
	return ecies.Encrypt(rand.Reader, eciesPubkey, msg, nil, nil)
}

func UnmarshalPubkey(data []byte) (*ecdsa.PublicKey, error) {
	pub, err := ec.DecodePublicKey(data, elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("deserializing public key failed: decode P-256 public key error")
	}

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: pub.X, Y: pub.Y}, nil
}

func DecryptMsg(ecdsaPrivkey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	prikey := ecies.ImportECDSA(ecdsaPrivkey)
	return prikey.Decrypt(msg, nil, nil)
}

func PrivateKeyToEcdsaPrivkey(data []byte) (*ecdsa.PrivateKey, error) {
	c, err := keypair.GetCurve(data[1])
	if err != nil {
		return nil, err
	}
	size := (c.Params().BitSize + 7) >> 3
	if len(data) < size*2+3 {
		return nil, fmt.Errorf("deserializing private key failed: not enough length")
	}

	return ec.ConstructPrivateKey(data[2:2+size], c), nil
}
