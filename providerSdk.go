package orange_provider_go_sdk

type OrangeProviderSdk interface {
	SignData(data []byte) ([]byte, error)
	VerifySig(did string, msgbytes []byte, sigbytes []byte) (bool, error)
	EncryptDataWithDID(data []byte, did string) ([]byte, error)
	DecryptData(data []byte) ([]byte, error)
	GetSelfDID() string
}
