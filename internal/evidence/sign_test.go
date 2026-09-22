package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	cose "github.com/veraison/go-cose"
)

func TestManifestSigningAndVerification(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifestForSigning()

	signed, err := SignManifest(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Signature != "" {
		t.Fatal("SignManifest mutated its input")
	}
	if signed.Signature == "" {
		t.Fatal("signed manifest has no signature")
	}
	if err := VerifyManifestSignature(signed, publicKey); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	signed.RunID = "tampered"
	if err := VerifyManifestSignature(signed, publicKey); err == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestManifestCOSESignatureVerifiesIndependently(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignManifest(validManifestForSigning(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signed.SignatureFormat != ManifestSignatureCOSE {
		t.Fatalf("signature format = %q", signed.SignatureFormat)
	}
	encoded, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(encoded); err != nil {
		t.Fatalf("signature is not a COSE_Sign1 envelope: %v", err)
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != cose.AlgorithmEdDSA {
		t.Fatalf("protected algorithm = %v", algorithm)
	}
	payload, err := manifestSigningPayload(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Payload, payload) {
		t.Fatal("COSE payload does not match the manifest signing payload")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := message.Verify(nil, verifier); err != nil {
		t.Fatalf("independent COSE verification failed: %v", err)
	}
}

func TestManifestSignatureRejectsCOSETampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func() RunEvidenceManifest {
		signed, err := SignManifest(validManifestForSigning(), privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	decode := func(m RunEvidenceManifest) cose.Sign1Message {
		raw, err := base64.StdEncoding.DecodeString(m.Signature)
		if err != nil {
			t.Fatal(err)
		}
		var message cose.Sign1Message
		if err := message.UnmarshalCBOR(raw); err != nil {
			t.Fatal(err)
		}
		return message
	}
	reseal := func(m RunEvidenceManifest, message cose.Sign1Message) RunEvidenceManifest {
		raw, err := message.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		m.Signature = base64.StdEncoding.EncodeToString(raw)
		return m
	}

	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		manifest RunEvidenceManifest
		key      ed25519.PublicKey
	}{
		{"wrong key", sign(), wrongKey},
		{"tampered manifest", func() RunEvidenceManifest {
			m := sign()
			m.RunID = "tampered"
			return m
		}(), publicKey},
		{"altered payload", func() RunEvidenceManifest {
			m := sign()
			message := decode(m)
			message.Payload = append(append([]byte(nil), message.Payload...), 'x')
			return reseal(m, message)
		}(), publicKey},
		{"altered signature", func() RunEvidenceManifest {
			m := sign()
			message := decode(m)
			message.Signature[0] ^= 0xff
			return reseal(m, message)
		}(), publicKey},
		{"unknown format", func() RunEvidenceManifest {
			m := sign()
			m.SignatureFormat = "none"
			return m
		}(), publicKey},
		{"algorithm mismatch", func() RunEvidenceManifest {
			m := sign()
			message := decode(m)
			message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
			message.Headers.RawProtected = nil
			return reseal(m, message)
		}(), publicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyManifestSignature(tc.manifest, tc.key); err == nil {
				t.Fatal("invalid COSE signature accepted")
			}
		})
	}
}

func TestManifestLegacyEmptyFormatSignatureStillAccepted(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifestForSigning()
	payload, err := manifestSigningPayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := VerifyManifestSignature(manifest, publicKey); err != nil {
		t.Fatalf("legacy empty-format signature rejected: %v", err)
	}
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)[:ed25519.SignatureSize-1])
	if err := VerifyManifestSignature(manifest, publicKey); err == nil {
		t.Fatal("truncated legacy signature accepted")
	}
}

func TestManifestSigningRejectsInvalidInputs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		manifest RunEvidenceManifest
		key      ed25519.PrivateKey
	}{
		{name: "invalid manifest", manifest: RunEvidenceManifest{}, key: privateKey},
		{name: "missing private key", manifest: validManifestForSigning()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SignManifest(tt.manifest, tt.key); err == nil {
				t.Fatal("invalid signing input accepted")
			}
		})
	}

	unsigned := validManifestForSigning()
	if err := VerifyManifestSignature(unsigned, publicKey); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
	unsigned.Signature = "not-base64"
	if err := VerifyManifestSignature(unsigned, publicKey); err == nil {
		t.Fatal("malformed signature accepted")
	}
	if err := VerifyManifestSignature(validManifestForSigning(), nil); err == nil {
		t.Fatal("missing public key accepted")
	}
}

func TestManifestSignatureIsCanonicalAcrossMapInsertionOrder(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := validManifestForSigning()
	a.RawChainHeads = map[string]string{"z": hash("z"), "a": hash("a")}
	b := validManifestForSigning()
	b.RawChainHeads = map[string]string{"a": hash("a"), "z": hash("z")}

	signedA, err := SignManifest(a, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signedB, err := SignManifest(b, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if signedA.Signature != signedB.Signature {
		t.Fatal("equivalent manifests produced different signatures")
	}
}

func validManifestForSigning() RunEvidenceManifest {
	digest := hash("manifest")
	return RunEvidenceManifest{
		SchemaVersion:            "v1",
		RunID:                    "run-1",
		RunSpecDigest:            digest,
		ObservationPlanDigest:    digest,
		CapabilityManifestDigest: digest,
		SensorHealthDigest:       digest,
		TrackedEventChainHead:    digest,
		RawChainHeads:            map[string]string{"sensor/boot": digest},
		Artifacts:                []ArtifactDigest{{Path: "tracked-events.jsonl", SHA256: digest, Size: 10}},
		MerkleRoot:               digest,
		SealedAt:                 time.Unix(1, 2).UTC(),
	}
}
