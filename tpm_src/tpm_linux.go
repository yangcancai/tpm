package tpm

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

type Sig struct {
	R *big.Int
	S *big.Int
}

type Tpm struct {
	key   *client.Key
	key64 string
}

func (t *Tpm) Open(privKey64 string) (err error) {
	tpmPth, err := getTpmPath()
	if err != nil {
		return
	}

	tpmDev, err := tpm2.OpenTPM(tpmPth)
	if err != nil {
		err = fmt.Errorf("tpm: Failed to open tpm %v", err)
		return
	}

	templ := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth |
			tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
		},
	}

	key, err := client.NewKey(tpmDev, tpm2.HandleOwner, templ)
	if err != nil {
		err = fmt.Errorf("tpm: Failed to create signing key %v", err)
		return
	}

	bytesPub, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		err = fmt.Errorf("tpm: Failed to marshal pub key %v", err)
		return
	}

	t.key = key
	t.key64 = base64.StdEncoding.EncodeToString(bytesPub)

	return
}

func (t *Tpm) Close() {
	t.key.Close()
}

func (t *Tpm) PublicKey() (pubKey64 string, err error) {
	pubKey64 = t.key64
	return
}

func (t *Tpm) Sign(data []byte) (privKey64, sig64 string, err error) {
	sig, err := t.key.SignData(data)
	if err != nil {
		err = fmt.Errorf("tpm: Failed to sign data %v", err)
		return
	}

	sig64 = base64.StdEncoding.EncodeToString(sig)

	return
}

func getTpmPath() (pth string, err error) {
	pth = "/dev/tpmrm0"
	exists, err := Exists(pth)
	if err != nil || exists {
		return
	}

	pth = "/dev/tpm0"
	exists, err = Exists(pth)
	if err != nil || exists {
		return
	}

	pth = "/dev/tpmrm1"
	exists, err = Exists(pth)
	if err != nil || exists {
		return
	}

	pth = "/dev/tpm1"
	exists, err = Exists(pth)
	if err != nil || exists {
		return
	}

	pth = "/dev/tpm"
	exists, err = Exists(pth)
	if err != nil || exists {
		return
	}

	err = fmt.Errorf("tpm: Failed to find TPM %v", err)

	return
}
