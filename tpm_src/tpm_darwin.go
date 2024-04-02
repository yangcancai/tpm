package tpm

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"

	"github.com/google/go-tpm-tools/client"
)

type authInput struct {
	KeyData string `json:"key_data"`
}

type authInput2 struct {
	SignData string `json:"sign_data"`
}

type authOutput struct {
	KeyData   string `json:"key_data"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type Tpm struct {
	cmd        *exec.Cmd
	stdout     io.ReadCloser
	stderr     *bytes.Buffer
	stdin      io.WriteCloser
	key        *client.Key
	waiter     chan bool
	waiterSet  bool
	exitWaiter chan bool
	privKey64  string
	pubKey64   string
	sig64      string
	readErr    error
	exitErr    error
}

func (t *Tpm) Open(privKey64 string) (err error) {
	t.waiter = make(chan bool, 8)
	t.exitWaiter = make(chan bool, 8)
	t.privKey64 = privKey64

	deviceAuthPth := getDeviceAuthPath()

	t.cmd = Command(deviceAuthPth)

	t.stderr = &bytes.Buffer{}
	t.cmd.Stderr = t.stderr

	t.stdout, err = t.cmd.StdoutPipe()
	if err != nil {
		return
	}

	t.stdin, err = t.cmd.StdinPipe()
	if err != nil {
		return
	}

	err = t.cmd.Start()
	if err != nil {
		t.Close()
		return
	}

	go t.reader()
	go t.wait()

	inputData := &authInput{
		KeyData: t.privKey64,
	}

	inputByt, err := json.Marshal(inputData)
	if err != nil {
		t.Close()
		return
	}

	err = t.write(inputByt)
	if err != nil {
		t.Close()
		return
	}

	return
}

func (t *Tpm) write(input []byte) (err error) {
	input = append(input, '\n')

	_, err = t.stdin.Write(input)
	if err != nil {
		return
	}

	return
}

func (t *Tpm) wait() {
	defer func() {
		t.exitWaiter <- true

		if !t.waiterSet {
			t.waiterSet = true
			t.waiter <- true
		}
	}()

	t.exitErr = t.cmd.Wait()
	errOutput := t.stderr.String()

	if t.exitErr != nil {
		fmt.Printf("%v", errOutput)
		return
	}
	return
}

func (t *Tpm) reader() {
	defer t.Close()

	reader := bufio.NewReader(t.stdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err == io.EOF {
			return
		} else if err != nil {
			t.readErr = fmt.Errorf("error read line")
			return
		}

		outputData := &authOutput{}

		err = json.Unmarshal(bytes.TrimSpace(line), outputData)
		if err != nil {
			t.readErr = fmt.Errorf("tpm: Failed to unmarshal output data %v", err)
			return
		}

		if outputData.KeyData != "" {
			t.privKey64 = outputData.KeyData
		}
		if outputData.PublicKey != "" {
			t.pubKey64 = outputData.PublicKey
		}
		if outputData.Signature != "" {
			t.sig64 = outputData.Signature
		}

		if !t.waiterSet {
			t.waiterSet = true
			t.waiter <- true
		}
	}
}

func (t *Tpm) Close() {
	defer func() {
		if !t.waiterSet {
			t.waiterSet = true
			t.waiter <- true
		}
	}()

	if t.stdout != nil {
		_ = t.stdout.Close()
	}
	if t.stdin != nil {
		_ = t.stdin.Close()
	}

	return
}
func (t *Tpm) PublicKey() (pubKey64 string, err error) {
	<-t.waiter

	err = t.exitErr
	if err != nil {
		return
	}

	err = t.readErr
	if err != nil {
		return
	}

	pubKey64 = t.pubKey64
	return
}

func (t *Tpm) Sign(data []byte) (privKey64, sig64 string, err error) {
	inputData := &authInput2{
		SignData: base64.StdEncoding.EncodeToString(data),
	}

	input, err := json.Marshal(inputData)
	if err != nil {
		err = fmt.Errorf("tpm: Failed to marshal input data %v", err)
		return
	}

	err = t.write(input)
	if err != nil {
		return
	}

	<-t.exitWaiter

	err = t.exitErr
	if err != nil {
		return
	}

	err = t.readErr
	if err != nil {
		return
	}

	privKey64 = t.privKey64
	sig64 = t.sig64

	return
}

func getDeviceAuthPath() string {
	return "./TpmAuth"
}
