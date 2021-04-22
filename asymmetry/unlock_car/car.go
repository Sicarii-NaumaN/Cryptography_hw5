package unlock_car

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func NewCar(openCode string, keyPair *rsa.PrivateKey, trinketKey *rsa.PublicKey) *Car {
	car := new(Car)
	car.Handshake = []byte(openCode)
	car.KeyPair = keyPair
	car.TrinketPublicKey = trinketKey
	return car
}

type Car struct {
	Handshake        []byte
	KeyPair          *rsa.PrivateKey
	TrinketPublicKey *rsa.PublicKey
	VerifyStringHash []byte
}

func (car *Car) CheckHandshake(hashMsg []byte) error {
	hashOpenMsg := sha256.New()
	_, err := hashOpenMsg.Write(car.Handshake)
	if err != nil {
		panic(err)
	}

	if bytes.Compare(hashOpenMsg.Sum(nil), hashMsg) != 0 {
		return errors.New("Wrong message")
	}

	return nil
}

// SendChallenge creates random string (using seed) to check trinket
func (car *Car) SendChallenge() []byte {
	sendingData := make([]rune, 128)
	for i := range sendingData {
		sendingData[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	msgHash := sha256.New()
	_, err := msgHash.Write([]byte(string(sendingData)))
	if err != nil {
		panic(err)
	}
	car.VerifyStringHash = msgHash.Sum(nil)

	return msgHash.Sum(nil)
}

func (car *Car) VerifyAccessAndSign(encryptedBytes []byte, signature []byte) error {
	decryptedBytes, err := car.KeyPair.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return err
	}

	if bytes.Compare(decryptedBytes, car.VerifyStringHash) != 0 {
		return errors.New("Not equal data")
	}

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	err = rsa.VerifyPSS(car.TrinketPublicKey, crypto.SHA256, decryptedBytes, signature, nil)
	if err != nil {
		return errors.New("could not verify signature: ")
	}

	return nil
}

func (car *Car) Open() string {
	return "Car opened!"
}
