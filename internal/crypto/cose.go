package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// COSE algorithm identifiers.
const (
	COSEAlgES256 = -7
	COSEAlgEdDSA = -8
)

// COSE key type identifiers.
const (
	COSEKeyTypeEC2 = 2 // Elliptic Curve (P-256, P-384, P-521)
	COSEKeyTypeOKP = 1 // Octet Key Pair (Ed25519)
)

// COSE elliptic curve identifiers.
const (
	COSECurveP256    = 1
	COSECurveEd25519 = 6
)

// LGI Pass software authenticator AAGUID (UUID v5 from DNS namespace + "lgipass.lancastergroup.com").
// Pre-computed: 5a2f7e8b-3c41-5d09-a1b6-4e8f2d7c9a03
var LGIPassAAGUID = [16]byte{
	0x5a, 0x2f, 0x7e, 0x8b, 0x3c, 0x41, 0x5d, 0x09,
	0xa1, 0xb6, 0x4e, 0x8f, 0x2d, 0x7c, 0x9a, 0x03,
}

// coseKeyMap represents a COSE key as a CBOR map.
type coseKeyMap map[int]interface{}

// MarshalCOSEKey encodes a public key as a COSE_Key structure in CBOR.
func MarshalCOSEKey(algorithm int, pub interface{}) ([]byte, error) {
	switch algorithm {
	case COSEAlgES256:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("expected *ecdsa.PublicKey for ES256")
		}
		if ecKey.Curve != elliptic.P256() {
			return nil, errors.New("expected P-256 curve for ES256")
		}
		x := ecKey.X.Bytes()
		y := ecKey.Y.Bytes()
		// Pad to 32 bytes
		for len(x) < 32 {
			x = append([]byte{0}, x...)
		}
		for len(y) < 32 {
			y = append([]byte{0}, y...)
		}
		m := coseKeyMap{
			1:  COSEKeyTypeEC2,    // kty
			3:  COSEAlgES256,      // alg
			-1: COSECurveP256,     // crv
			-2: x,                 // x
			-3: y,                 // y
		}
		return cbor.Marshal(m)

	case COSEAlgEdDSA:
		edKey, ok := pub.([]byte)
		if !ok {
			return nil, errors.New("expected []byte (ed25519 public key) for EdDSA")
		}
		if len(edKey) != 32 {
			return nil, errors.New("ed25519 public key must be 32 bytes")
		}
		m := coseKeyMap{
			1:  COSEKeyTypeOKP,    // kty
			3:  COSEAlgEdDSA,      // alg
			-1: COSECurveEd25519,  // crv
			-2: edKey,             // x
		}
		return cbor.Marshal(m)

	default:
		return nil, fmt.Errorf("unsupported COSE algorithm: %d", algorithm)
	}
}

// UnmarshalCOSEKey decodes a COSE_Key from CBOR and returns the public key and algorithm.
func UnmarshalCOSEKey(coseKey []byte) (interface{}, int, error) {
	var m map[int]cbor.RawMessage
	if err := cbor.Unmarshal(coseKey, &m); err != nil {
		return nil, 0, fmt.Errorf("unmarshal COSE key: %w", err)
	}

	var alg int
	if raw, ok := m[3]; ok {
		if err := cbor.Unmarshal([]byte(raw), &alg); err != nil {
			return nil, 0, fmt.Errorf("unmarshal algorithm: %w", err)
		}
	}

	var kty int
	if raw, ok := m[1]; ok {
		if err := cbor.Unmarshal([]byte(raw), &kty); err != nil {
			return nil, 0, fmt.Errorf("unmarshal key type: %w", err)
		}
	}

	switch kty {
	case COSEKeyTypeEC2:
		var x, y []byte
		if raw, ok := m[-2]; ok {
			if err := cbor.Unmarshal([]byte(raw), &x); err != nil {
				return nil, 0, fmt.Errorf("unmarshal x coordinate: %w", err)
			}
		}
		if raw, ok := m[-3]; ok {
			if err := cbor.Unmarshal([]byte(raw), &y); err != nil {
				return nil, 0, fmt.Errorf("unmarshal y coordinate: %w", err)
			}
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		return pub, alg, nil

	case COSEKeyTypeOKP:
		var x []byte
		if raw, ok := m[-2]; ok {
			if err := cbor.Unmarshal([]byte(raw), &x); err != nil {
				return nil, 0, fmt.Errorf("unmarshal ed25519 key: %w", err)
			}
		}
		return x, alg, nil

	default:
		return nil, 0, fmt.Errorf("unsupported COSE key type: %d", kty)
	}
}

// Authenticator data flags.
const (
	FlagUserPresent  byte = 0x01 // UP
	FlagUserVerified byte = 0x04 // UV
	FlagAttestedCred byte = 0x40 // AT
	FlagExtensions   byte = 0x80 // ED
	FlagBackupElig   byte = 0x08 // BE
	FlagBackupState  byte = 0x10 // BS
)

// COSEKeyToSPKI converts a COSE public key to SubjectPublicKeyInfo (DER) format.
// This is what AuthenticatorAttestationResponse.getPublicKey() returns per the WebAuthn spec.
func COSEKeyToSPKI(coseKey []byte) ([]byte, error) {
	pub, _, err := UnmarshalCOSEKey(coseKey)
	if err != nil {
		return nil, err
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type for SPKI export")
	}
}

// MarshalAuthenticatorData builds the authenticator data binary structure.
// attestedCred is optional (nil for assertion, non-nil for attestation).
func MarshalAuthenticatorData(rpIDHash [32]byte, flags byte, signCount uint32, attestedCred []byte) []byte {
	// authData = rpIdHash (32) + flags (1) + signCount (4) + [attestedCredentialData] + [extensions]
	size := 32 + 1 + 4 + len(attestedCred)
	data := make([]byte, size)

	copy(data[0:32], rpIDHash[:])
	data[32] = flags
	binary.BigEndian.PutUint32(data[33:37], signCount)
	if len(attestedCred) > 0 {
		copy(data[37:], attestedCred)
	}

	return data
}

// ParseAuthenticatorData parses the binary authenticator data structure.
func ParseAuthenticatorData(data []byte) (rpIDHash [32]byte, flags byte, signCount uint32, attestedCred []byte, err error) {
	if len(data) < 37 {
		return rpIDHash, 0, 0, nil, errors.New("authenticator data too short")
	}

	copy(rpIDHash[:], data[0:32])
	flags = data[32]
	signCount = binary.BigEndian.Uint32(data[33:37])

	if flags&FlagAttestedCred != 0 && len(data) > 37 {
		attestedCred = data[37:]
	}

	return rpIDHash, flags, signCount, attestedCred, nil
}

// BuildAttestedCredentialData builds the attested credential data portion of authenticator data.
func BuildAttestedCredentialData(aaguid [16]byte, credentialID, publicKeyCBOR []byte) []byte {
	// aaguid (16) + credIdLen (2) + credentialId + publicKey
	size := 16 + 2 + len(credentialID) + len(publicKeyCBOR)
	data := make([]byte, size)

	copy(data[0:16], aaguid[:])
	binary.BigEndian.PutUint16(data[16:18], uint16(len(credentialID))) // #nosec G115 -- credential IDs are always < 1024 bytes
	copy(data[18:18+len(credentialID)], credentialID)
	copy(data[18+len(credentialID):], publicKeyCBOR)

	return data
}

// MarshalAttestationObject builds the attestation object CBOR structure.
func MarshalAttestationObject(fmtStr string, authData []byte) ([]byte, error) {
	obj := map[string]interface{}{
		"fmt":     fmtStr,
		"attStmt": map[string]interface{}{},
		"authData": authData,
	}
	return cbor.Marshal(obj)
}

// MarshalPackedAttestationObject builds a "packed" self-attestation object.
// For self-attestation, the attStmt contains alg + sig (signed over authData || clientDataHash).
func MarshalPackedAttestationObject(authData, signature []byte, algorithm int) ([]byte, error) {
	obj := map[string]interface{}{
		"fmt": "packed",
		"attStmt": map[int]interface{}{
			// CBOR uses integer keys: "alg" = 1, "sig" = 2 per WebAuthn spec
			// But the WebAuthn spec actually uses string keys for attStmt
		},
		"authData": authData,
	}
	// For packed self-attestation, attStmt uses string keys
	obj["attStmt"] = map[string]interface{}{
		"alg": algorithm,
		"sig": signature,
	}
	return cbor.Marshal(obj)
}

// ExtractAAGUIDFromAttestation extracts the AAGUID from a CBOR attestation object.
func ExtractAAGUIDFromAttestation(attestBytes []byte) ([]byte, error) {
	var obj struct {
		AuthData []byte `cbor:"authData"`
	}
	if err := cbor.Unmarshal(attestBytes, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal attestation: %w", err)
	}
	return ExtractAAGUIDFromAuthData(obj.AuthData)
}

// ExtractAAGUIDFromAuthData extracts the AAGUID from raw authenticator data.
// AAGUID is at bytes 37-53 (after rpIdHash[32] + flags[1] + signCount[4]).
func ExtractAAGUIDFromAuthData(authData []byte) ([]byte, error) {
	if len(authData) < 55 {
		return nil, fmt.Errorf("authData too short for AAGUID (%d bytes)", len(authData))
	}
	aaguid := make([]byte, 16)
	copy(aaguid, authData[37:53])
	return aaguid, nil
}

// RPIDHash computes SHA-256 hash of the relying party ID.
func RPIDHash(rpID string) [32]byte {
	return sha256.Sum256([]byte(rpID))
}
