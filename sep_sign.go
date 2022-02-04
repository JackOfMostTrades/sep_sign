//go:build darwin
// +build darwin

package sep_sign

import (
	"crypto"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

//go:generate swiftc -target x86_64-apple-macos11.0 -o sep_sign-amd64 main.swift
//go:generate swiftc -target arm64-apple-macos11.0 -o sep_sign-arm64 main.swift
//go:generate lipo -create sep_sign-amd64 sep_sign-arm64 -o sep_sign
//go:generate strip sep_sign

//go:embed sep_sign
var _SEP_SIGN_BINARY []byte

type execOutput struct {
	IsAvailable bool   `json:"isAvailable"`
	PrivateKey  []byte `json:"privateKey"`
	PublicKey   []byte `json:"publicKey"`
	Signature   []byte `json:"signature"`
}

func execBinary(args ...string) (*execOutput, error) {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary file for sep_sign binary: %v", err)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	_, err = file.Write(_SEP_SIGN_BINARY)
	if err != nil {
		return nil, fmt.Errorf("failed to write sep_sign binary bytes to file: %v", err)
	}
	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close file: %v", err)
	}
	err = os.Chmod(file.Name(), 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to chmod sep_sign binary: %v", err)
	}

	cmd := exec.Command(file.Name(), args...)
	cmd.Stderr = os.Stderr
	outputReader, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to connect pipe to cmd stdout: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start command: %v", err)
	}
	output := new(execOutput)
	err = json.NewDecoder(outputReader).Decode(output)
	if err != nil {
		return nil, fmt.Errorf("failed to JSON decode sep_sign output: %v", err)
	}
	err = outputReader.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close stdout reader: %v", err)
	}
	err = cmd.Wait()
	if err != nil {
		return nil, fmt.Errorf("failed to wait for command to complete: %v", err)
	}
	return output, nil
}

func IsAvailable() (bool, error) {
	output, err := execBinary()
	if err != nil {
		return false, err
	}
	return output.IsAvailable, nil
}

func Generate() ([]byte, crypto.PublicKey, error) {
	output, err := execBinary("--generate")
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse returned public key: %v", err)
	}
	return output.PrivateKey, publicKey, nil
}

func SignData(privateKey []byte, data []byte) ([]byte, error) {
	output, err := execBinary("--key", base64.StdEncoding.EncodeToString(privateKey),
		"--data", base64.StdEncoding.EncodeToString(data))
	if err != nil {
		return nil, err
	}
	return output.Signature, nil
}
