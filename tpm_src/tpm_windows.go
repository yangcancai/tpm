package tpm

import (
	"crypto/x509"
	"encoding/base64"
	"math/big"

	"github.com/dropbox/godropbox/errors"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/pritunl/pritunl-client-electron/service/errortypes"
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
	tpmDev, err := tpm2.OpenTPM()
	if err != nil {
		err = &errortypes.ReadError{
			errors.Wrap(err, "tpm: Failed to open tpm"),
		}
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
		err = &errortypes.ReadError{
			errors.Wrap(err, "tpm: Failed to create signing key"),
		}
		return
	}

	bytesPub, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		err = &errortypes.ParseError{
			errors.Wrap(err, "tpm: Failed to marshal pub key"),
		}
		return
	}

	t.key = key
	t.key64 = base64.RawStdEncoding.EncodeToString(bytesPub)

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
		err = &errortypes.ParseError{
			errors.Wrap(err, "tpm: Failed to sign data"),
		}
		return
	}

	sig64 = base64.RawStdEncoding.EncodeToString(sig)

	return
}
