package main

import (
	. "asymmetry/unlock_car"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	_ "log"
	_ "math/big"
)

func main() {
	// The public key is a part of the *rsa.PrivateKey struct
	CarKeysPair, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	TrinketKeysPair, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n0: (registration) %x (pubkey1 written to trinked), %x (pubkey2 written to car)\n",
		CarKeysPair.PublicKey, TrinketKeysPair.PublicKey)

	car := NewCar("Audi rs7", CarKeysPair, &TrinketKeysPair.PublicKey)
	trinket := NewTrinket("Audi rs7", TrinketKeysPair, &CarKeysPair.PublicKey)

	Handshake := trinket.SendSignal()

	err = car.CheckHandshake(Handshake)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n1: (handshake) trinket -> car, %x (challenge for car)\n",
		Handshake)

	challenge := car.SendChallenge()
	fmt.Printf("\n2: (challenge) car -> trinket: %x (challenge for trinket)\n",
		challenge)
	if challenge == nil {
		log.Fatal("Error with challenge")
	}

	encryptedBytes, signature := trinket.ChallengeResponse(challenge)
	if encryptedBytes == nil || signature == nil {
		log.Fatal("Error with challenge response")
	}

	fmt.Printf("\n3: (response) trinket->car: %x (confirm challenge for trinket), %x (signature)\n",
		encryptedBytes, signature)

	result := "ok, OPEN DOOR"
	err = car.VerifyAccessAndSign(encryptedBytes, signature)
	if err != nil {
		result = "error"
	}

	fmt.Printf("\n4: (action) car: check response - %s\n", result)
}
