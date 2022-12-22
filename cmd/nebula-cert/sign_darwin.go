package main

// #cgo LDFLAGS: -L${SRCDIR}/../../lib -lSEP256
// #include "../../lib/SEP256.h"
import "C"

func seP256Keypair() ([]byte, []byte) {
	privateKeyHandle := make([]C.char, 300)
	length := C.int(300)
	result := C.CreateSEP256Key(&privateKeyHandle[0], &length)
	if !result {
		panic("Failed to create new private key")
	}

	privKey := make([]byte, length)
	for i := 0; i < (int)(length); i++ {
		privKey[i] = (byte)(privateKeyHandle[i])
	}

	pubBuffer := make([]C.char, 65)
	pubLength := C.int(65)
	result = C.GetSEP256PublicKey(&privateKeyHandle[0], length, &pubBuffer[0], &pubLength)
	if !result {
		panic("Failed to get public key")
	}

	pubKey := make([]byte, pubLength)
	for i := 0; i < (int)(pubLength); i++ {
		pubKey[i] = (byte)(pubBuffer[i])
	}

	return pubKey, privKey
}
