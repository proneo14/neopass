package crypto

// FIDOMetadataStatement returns a FIDO Metadata Service v3 metadata statement
// for the LGI Pass software authenticator. This is served at a well-known
// endpoint and can be submitted to the FIDO Alliance Metadata Service.
//
// See: https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html
func FIDOMetadataStatement() map[string]interface{} {
	return map[string]interface{}{
		"legalHeader":    "https://fidoalliance.org/metadata/metadata-statement-legal-header/",
		"aaguid":         "5a2f7e8b-3c41-5d09-a1b6-4e8f2d7c9a03",
		"description":    "LGI Pass Software Authenticator",
		"authenticatorVersion": 1,
		"protocolFamily": "fido2",
		"schema":         3,
		"upv": []map[string]int{
			{"major": 1, "minor": 1},
			{"major": 1, "minor": 0},
		},
		"authenticationAlgorithms": []string{"secp256r1_ecdsa_sha256_raw", "ed25519_eddsa_sha512_raw"},
		"publicKeyAlgAndEncodings": []string{"cose"},
		"attestationTypes":         []string{"basic_surrogate"},
		"userVerificationDetails": [][]map[string]interface{}{
			{{"userVerificationMethod": "passcode_internal"}},
			{{"userVerificationMethod": "presence_internal"}},
		},
		"keyProtection":       []string{"software"},
		"matcherProtection":   []string{"software"},
		"cryptoStrength":      128,
		"attachmentHint":      []string{"internal"},
		"tcDisplay":           []string{},
		"attestationRootCertificates": []string{}, // self-attestation, no root cert
		"icon": "data:image/png;base64,", // placeholder — would be a real icon
		"supportedExtensions": []map[string]interface{}{
			{"id": "credProtect", "fail_if_unknown": false},
		},
		"authenticatorGetInfo": map[string]interface{}{
			"versions":   []string{"FIDO_2_0", "FIDO_2_1"},
			"extensions": []string{"credProtect"},
			"aaguid":     "5a2f7e8b3c415d09a1b64e8f2d7c9a03",
			"options": map[string]bool{
				"plat": true,
				"rk":   true,
				"up":   true,
				"uv":   true,
			},
			"maxMsgSize":              2048,
			"pinUvAuthProtocols":      []int{1},
			"maxCredentialCountInList": 100,
			"maxCredentialIdLength":    128,
			"transports":              []string{"internal"},
			"algorithms": []map[string]interface{}{
				{"type": "public-key", "alg": -7},  // ES256
				{"type": "public-key", "alg": -8},  // EdDSA
			},
		},
	}
}
