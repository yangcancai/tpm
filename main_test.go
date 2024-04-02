package main

import (
	"testing"

	tpm "github.com/yangcanca/tpm/tpm_src"
)

func TestSign(t *testing.T) {
	instance := &tpm.Tpm{}
	err := instance.Open("")
	if err != nil {
		t.Errorf("init tpm error %v", err)
		return
	}
	publicKey, err := instance.PublicKey()
	if err != nil {
		t.Errorf("init tpm error %v", err)
		return
	}
	data := []byte("hello")
	continueKey, sign, _ := instance.Sign(data)
	valid, err := tpm.VerifySignature(publicKey, sign, data)
	if valid != true || err != nil {
		t.Errorf("pubkey: %s, sign: %s, data: %s", publicKey, sign, data)
		t.Errorf("valid %v %v", valid, err)
	}
	instance = &tpm.Tpm{}
	err = instance.Open(continueKey)
	if err != nil {
		t.Errorf("init tpm error %v", err)
	}
	publicKey1, err := instance.PublicKey()
	if publicKey != publicKey1 {
		t.Errorf("init tpm error %v", err)
		return
	}
	data = []byte("yes")
	continueKey1, sign, _ := instance.Sign(data)
	if continueKey != continueKey1 {
		t.Errorf("continuekey error %v", continueKey1)
	}
	valid, err = tpm.VerifySignature(publicKey, sign, data)
	if valid != true || err != nil {
		t.Errorf("pubkey: %s, sign: %s, data: %s", publicKey, sign, data)
		t.Errorf("valid %v %v", valid, err)
	}
}
