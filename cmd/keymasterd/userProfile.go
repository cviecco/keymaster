package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"github.com/cviecco/webauthn/webauthn"
	"time"
)

// This is the implementation of duo-labs' webauthn User interface
// https://github.com/duo-labs/webauthn/blob/master/webauthn/user.go

func (u *userProfile) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.WebauthnID))
	return buf
	//return nil
}

func (u *userProfile) WebAuthnName() string {
	return u.Username
}

func (u *userProfile) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *userProfile) WebAuthnIcon() string {
	return "Not implemented"
}
func (u *userProfile) WebAuthnCredentials() []webauthn.Credential {
	var rvalue []webauthn.Credential
	for _, authData := range u.WebauthnData {
		if !authData.Enabled {
			continue
		}
		logger.Debugf(2, "native webauth credential=%+v", authData.Credential)
		rvalue = append(rvalue, authData.Credential)
	}
	for _, u2fData := range u.U2fAuthData {
		if !u2fData.Enabled {
			continue
		}
		pubkey, err := x509.MarshalPKIXPublicKey(&u2fData.Registration.PubKey)
		if err != nil {
			logger.Printf("error marshaling pub key=%+v", u2fData.Registration.PubKey)
			continue
		}
		/*
				keyID, _ := base64.StdEncoding.DecodeString(encodedKeyHandleIDHere)
			pubkey, _ := base64.StdEncoding.DecodeString(encodedPubKeyHere)
		*/

		credential := webauthn.Credential{
			ID:              u2fData.Registration.KeyHandle,
			PublicKey:       pubkey,
			AttestationType: "fido-u2f", // Also tried with this commented.
			Authenticator: webauthn.Authenticator{
				SignCount: u2fData.Counter,
				AAGUID:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		}
		logger.Debugf(2, "native u2f migration credential=%+v", credential)
		rvalue = append(rvalue, credential)
	}

	return rvalue
}

// This function will eventualy also do migration of credential data if needed
func (u *userProfile) FixupCredential(username string, displayname string) {
	if u.DisplayName == "" {
		u.DisplayName = displayname
	}
	// Check for nil....
	if u.WebauthnID == 0 {
		buf := make([]byte, 8)
		rand.Read(buf)
		u.WebauthnID = binary.LittleEndian.Uint64(buf)
	}
	if u.Username == "" {
		u.Username = displayname
	}
	if u.WebauthnData == nil {
		u.WebauthnData = make(map[int64]*webauthAuthData)
	}
}

/// next are not actually from there... but make it simpler
func (u *userProfile) AddWebAuthnCredential(cred webauthn.Credential) error {
	index := time.Now().Unix()
	authData := webauthAuthData{
		CreatedAt:  time.Now(),
		Enabled:    true,
		Credential: cred,
	}
	u.WebauthnData[index] = &authData
	return nil
}
