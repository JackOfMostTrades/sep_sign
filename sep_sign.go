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
	"os"
	"os/exec"
	"path/filepath"
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

func execBinary(appName string, args ...string) (*execOutput, error) {
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory for sep_sign binary: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fileName := appName
	if fileName == "" {
		fileName = "sep_sign"
	}
	file, err := os.OpenFile(filepath.Join(tmpDir, fileName), os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporory file for sep_sign binary: %v", err)
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
	output, err := execBinary("")
	if err != nil {
		return false, err
	}
	return output.IsAvailable, nil
}

type GenerateOptions struct {
	RequireBiometry bool
	RequireUnlocked bool
}

func Generate(options *GenerateOptions) ([]byte, crypto.PublicKey, error) {
	args := []string{"--generate"}
	if options != nil && options.RequireBiometry {
		args = append(args, "--requireBiometry")
	}
	if options != nil && options.RequireUnlocked {
		args = append(args, "--requireUnlocked")
	}

	output, err := execBinary("", args...)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := x509.ParsePKIXPublicKey(output.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse returned public key: %v", err)
	}
	return output.PrivateKey, publicKey, nil
}

type SignOptions struct {
	PrivateKey []byte
	Data       []byte
	AppName    string
}

func SignData(options *SignOptions) ([]byte, error) {
	if options == nil {
		return nil, fmt.Errorf("options argument is required")
	}

	output, err := execBinary(options.AppName, "--key", base64.StdEncoding.EncodeToString(options.PrivateKey),
		"--data", base64.StdEncoding.EncodeToString(options.Data))
	if err != nil {
		return nil, err
	}
	return output.Signature, nil
}
