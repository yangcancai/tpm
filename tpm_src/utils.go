package tpm

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
)

func DecodeBase64PublicKey(publicKeyBase64 string) (*ecdsa.PublicKey, error) {

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode the  publickeyBase64: %v", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %v", err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("to ecdsa publickey error")
	}

	return ecdsaPublicKey, nil
}
func DecodeBase64Signature(signatureBase64 string) (*big.Int, *big.Int, error) {

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode the signatureBase64 error: %v", err)
	}

	var signature struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(signatureBytes, &signature)
	if err != nil {
		return nil, nil, fmt.Errorf("decode signatureBytes to R S error: %v", err)
	}

	return signature.R, signature.S, nil
}
func VerifySignature(publickeyStr, signature string, messageBytes []byte) (bool, error) {
	publicKey, err := DecodeBase64PublicKey(publickeyStr)
	if err != nil {
		return false, err
	}
	r, s, err := DecodeBase64Signature(signature)
	if err != nil {
		return false, err
	}
	hashed := sha256.Sum256(messageBytes)

	if ecdsa.Verify(publicKey, hashed[:], r, s) {
		return true, nil
	} else {
		return false, nil
	}
}
func Command(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	return cmd
}
func Exists(pth string) (exists bool, err error) {
	_, err = os.Stat(pth)
	if err == nil {
		exists = true
		return
	}

	if os.IsNotExist(err) {
		err = nil
		return
	}
	err = fmt.Errorf("% utils: Failed to stat %s", err, pth)
	return
}
