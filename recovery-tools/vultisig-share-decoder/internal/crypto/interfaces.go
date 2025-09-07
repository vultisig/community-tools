package tss

type Service interface {
  // KeygenECDSA generates a new ECDSA keypair
  KeygenECDSA(req *KeygenRequest) (*KeygenResponse, error)
  // KeygenEDDSA generates a new EDDSA keypair
  KeygenEdDSA(req *KeygenRequest) (*KeygenResponse, error)
  // KeysignECDSA signs a message using ECDSA
  KeysignECDSA(req *KeysignRequest) (*KeysignResponse, error)
  // KeysignEDDSA signs a message using EDDSA
  KeysignEdDSA(req *KeysignRequest) (*KeysignResponse, error)
  // ApplyData applies the keygen data to the service
  ApplyData(string) error
}

type Messenger interface {
  Send(from, to, body string) error
}

type LocalStateAccessor interface {
  GetLocalState(pubKey string) (string, error)
  SaveLocalState(pubkey, localState string) error
}