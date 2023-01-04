package noiseutil

// #cgo LDFLAGS: -L${SRCDIR}/../lib -lSEP256
// #include "../lib/SEP256.h"
import "C"
import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"github.com/google/go-tpm/tpm2"
)

// DHP256 is the NIST P-256 ECDH function
var DHP256 noise.DHFunc = newNISTCurve("P256", elliptic.P256())

type nistCurve struct {
	name   string
	curve  elliptic.Curve
	dhLen  int
	pubLen int
}

func newNISTCurve(name string, curve elliptic.Curve) nistCurve {
	byteLen := (curve.Params().BitSize + 7) / 8
	return nistCurve{
		name:  name,
		curve: curve,
		dhLen: byteLen,
		// Standard uncompressed format, type (1 byte) plus both coordinates
		pubLen: 1 + 2*byteLen,
	}
}

func (c nistCurve) GenerateKeypair(rng io.Reader) (noise.DHKey, error) {

	if rng == nil {
		rng = rand.Reader
	}
	privkey, x, y, err := elliptic.GenerateKey(c.curve, rng)
	if err != nil {
		return noise.DHKey{}, err
	}
	pubkey := elliptic.Marshal(c.curve, x, y)
	return noise.DHKey{Private: privkey, Public: pubkey}, nil
}

func (c nistCurve) DH(privkey, pubkey []byte) ([]byte, error) {
	// determine what type of private key based on key length

	fmt.Println("Key length:")
	fmt.Println(len(privkey))

	switch {
	case len(privkey) > 65:
		private := make([]C.char, len(privkey))
		for i := 0; i < len(privkey); i++ {
			private[i] = (C.char)(privkey[i])
		}
		public := make([]C.char, len(pubkey))
		for i := 0; i < len(pubkey); i++ {
			public[i] = (C.char)(pubkey[i])
		}
		secretLength := C.int(64)
		secretChars := make([]C.char, secretLength)
		result := C.SEP256KeyAgreement(&private[0], (C.int)(len(privkey)), &public[0], (C.int)(len(pubkey)), &secretChars[0], &secretLength)
		if !result {
			return nil, errors.New("no support for Secure Enclave")
		}
		secret := make([]byte, secretLength)
		for i := 0; i < (int)(secretLength); i++ {
			secret[i] = (byte)(secretChars[i])
		}
		return secret, nil
	case len(privkey) == 65:

		defaultPassword := "\x01\x02\x03\x04"

		rw, err := tpm2.OpenTPM()
		if err != nil {
			return nil, errors.New("unable to open TPM")
		}

		defer rw.Close()

		// Generate a key in the TPM.
		// This uses the default P256 key template, and will get the same key each time this operation is done
		handle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, tpm2.PCRSelection{}, "", defaultPassword, tpm2.Public{
			Type:       tpm2.AlgECC,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagDecrypt | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
			ECCParameters: &tpm2.ECCParams{
				CurveID: tpm2.CurveNISTP256,
			},
		})
		if err != nil {
			return nil, errors.New("unable to recreate TPM key")
		}

		defer tpm2.FlushContext(rw, handle)

		x, y := elliptic.Unmarshal(c.curve, pubkey)
		z, err := tpm2.ECDHZGen(rw, handle, defaultPassword, tpm2.ECPoint{
			XRaw: x.Bytes(),
			YRaw: y.Bytes(),
		})
		if err != nil || z == nil {
			return nil, errors.New("unable to perform key exchange")
		}

		return z.XRaw, nil
	default:
		// based on stdlib crypto/tls/key_schedule.go
		// - https://github.com/golang/go/blob/go1.19/src/crypto/tls/key_schedule.go#L167-L178
		// Unmarshal also checks whether the given point is on the curve.
		x, y := elliptic.Unmarshal(c.curve, pubkey)
		if x == nil {
			return nil, errors.New("unable to unmarshal pubkey")
		}

		xShared, _ := c.curve.ScalarMult(x, y, privkey)
		sharedKey := make([]byte, c.dhLen)
		return xShared.FillBytes(sharedKey), nil
	}
}

func (c nistCurve) DHLen() int {
	// NOTE: Noise Protocol specifies "DHLen" to represent two things:
	// - The size of the public key
	// - The return size of the DH() function
	// But for standard NIST ECDH, the sizes of these are different.
	// Luckily, the flynn/noise library actually only uses this DHLen()
	// value to represent the public key size, so that is what we are
	// returning here. The length of the DH() return bytes are unaffected by
	// this value here.
	return c.pubLen
}
func (c nistCurve) DHName() string { return c.name }
