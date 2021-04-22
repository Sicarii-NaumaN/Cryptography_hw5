package unlock_car

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func NewTrinket(openCode string, keyPair *rsa.PrivateKey, carPublicKey *rsa.PublicKey) *Trinket {
	trinket := new(Trinket)
	trinket.Handshake = []byte(openCode)
	trinket.CarPublicKey = carPublicKey
	trinket.KeyPair = keyPair
	return trinket
}

type Trinket struct {
	Handshake    []byte
	CarPublicKey *rsa.PublicKey
	KeyPair      *rsa.PrivateKey
}

func (trinket *Trinket) SendSignal() []byte {
	hashOpenMsg := sha256.New()
	_, err := hashOpenMsg.Write(trinket.Handshake)
	if err != nil {
		panic(err)
	}

	return hashOpenMsg.Sum(nil)
}

// crypto/rand.Reader is a good source of entropy for randomizing the encryption function.
func (trinket *Trinket) ChallengeResponse(challenge []byte) ([]byte, []byte) {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		trinket.CarPublicKey,
		challenge,
		nil)
	if err != nil {
		panic(err)
	}

	//In order to generate the signature, we provide a random number generator,
	// our private key, the hashing algorithm that we used, and the hash sum
	// of our message (challenge)
	signature, err := rsa.SignPSS(rand.Reader, trinket.KeyPair, crypto.SHA256, challenge, nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes, signature
}
