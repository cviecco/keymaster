package fido

import (
	"bytes"
	_ "embed"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

//go:embed blob.jwt
var fidoMdsBytes []byte

func getBuiltIn() (*metadata.Metadata, error) {
	mdsReader := bytes.NewReader(fidoMdsBytes)
	decoder, err := metadata.NewDecoder(metadata.WithIgnoreEntryParsingErrors())
	if err != nil {
		return nil, err
	}
	payload, err := decoder.Decode(mdsReader)
	if err != nil {
		return nil, err
	}
	return decoder.Parse(payload)
}

// GetProvider returns a metadata.Provider backed by the embedded FIDO MDS
// blob. Entries are indexed both by AAGUID and by attestation certificate
// key identifier, the latter is needed for fido-u2f authenticators which
// report a zero AAGUID.
func GetProvider() (provider metadata.Provider, err error) {
	builtInMds, err := getBuiltIn()
	if err != nil {
		return nil, err
	}
	return memory.New(
		memory.WithMetadata(builtInMds.ToMap()),
		memory.WithMetadataKeyIdentifiers(builtInMds.ToKeyIdentifierMap()),
		memory.WithValidateEntryKeyIdentifier(true),
	)
}
