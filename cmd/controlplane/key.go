package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func developmentSigningKey(root string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	privatePath := filepath.Join(root, "dev-signing-key.ed25519")
	if existing, err := os.ReadFile(privatePath); err == nil {
		if len(existing) != ed25519.PrivateKeySize {
			return nil, errors.New("development signing key has invalid length")
		}
		if err := ensurePublicKey(root, ed25519.PrivateKey(existing).Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(existing), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return developmentSigningKey(root)
	}
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(privateKey); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	if err := ensurePublicKey(root, publicKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func ensurePublicKey(root string, publicKey ed25519.PublicKey) error {
	path := filepath.Join(root, "dev-signing-key.ed25519.pub")
	if existing, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(existing, publicKey) {
			return errors.New("development public key does not match private key")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return ensurePublicKey(root, publicKey)
	}
	if err != nil {
		return fmt.Errorf("create development public key: %w", err)
	}
	if _, err := file.Write(publicKey); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
