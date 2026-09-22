package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	cose "github.com/veraison/go-cose"
)

const manifestSignatureDomain = "HTB/run-evidence-manifest-signature/v1\x00"

const ManifestSignatureCOSE = "cose-sign1-ed25519"

// SignManifest returns a signed copy of manifest. The signature covers a
// domain-separated canonical JSON representation with the signature field
// omitted, so callers cannot accidentally sign a self-referential value.
func SignManifest(manifest RunEvidenceManifest, privateKey ed25519.PrivateKey) (RunEvidenceManifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return RunEvidenceManifest{}, errors.New("invalid Ed25519 private key")
	}
	manifest.SignatureFormat = ManifestSignatureCOSE
	payload, err := manifestSigningPayload(manifest)
	if err != nil {
		return RunEvidenceManifest{}, err
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, privateKey)
	if err != nil {
		return RunEvidenceManifest{}, fmt.Errorf("create COSE signer: %w", err)
	}
	encoded, err := cose.Sign1(rand.Reader, signer, cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmEdDSA}}, payload, nil)
	if err != nil {
		return RunEvidenceManifest{}, fmt.Errorf("sign COSE manifest: %w", err)
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(encoded)
	return manifest, nil
}

// VerifyManifestSignature validates both the manifest contract and its
// development Ed25519 signature.
func VerifyManifestSignature(manifest RunEvidenceManifest, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if manifest.Signature == "" {
		return errors.New("manifest is unsigned")
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return errors.New("manifest has invalid signature encoding")
	}
	payload, err := manifestSigningPayload(manifest)
	if err != nil {
		return err
	}
	switch manifest.SignatureFormat {
	case "":
		if len(signature) != ed25519.SignatureSize {
			return errors.New("manifest has invalid signature encoding")
		}
		if !ed25519.Verify(publicKey, payload, signature) {
			return errors.New("manifest signature verification failed")
		}
		return nil
	case ManifestSignatureCOSE:
		var message cose.Sign1Message
		if err := message.UnmarshalCBOR(signature); err != nil {
			return errors.New("manifest has invalid COSE signature encoding")
		}
		algorithm, err := message.Headers.Protected.Algorithm()
		if err != nil || algorithm != cose.AlgorithmEdDSA {
			return errors.New("manifest COSE signature has unexpected algorithm")
		}
		if !bytes.Equal(message.Payload, payload) {
			return errors.New("manifest COSE payload does not match signed manifest")
		}
		verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
		if err != nil {
			return fmt.Errorf("create COSE verifier: %w", err)
		}
		if err := message.Verify(nil, verifier); err != nil {
			return errors.New("manifest signature verification failed")
		}
		return nil
	default:
		return errors.New("manifest has unsupported signature format")
	}
}

func manifestSigningPayload(manifest RunEvidenceManifest) ([]byte, error) {
	manifest.Signature = ""
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	payload := make([]byte, 0, len(manifestSignatureDomain)+len(encoded))
	payload = append(payload, manifestSignatureDomain...)
	payload = append(payload, encoded...)
	return payload, nil
}
