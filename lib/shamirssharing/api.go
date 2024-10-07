package shamirssharing

import "github.com/Cloud-Foundations/golib/pkg/log"

type SharePrivateDoc struct {
	Version     int
	KeyIdentity string
	SecretShare []byte
}

type SharePublicDescriptor struct {
	Fingerprint    []byte
	KeyIdentity    string
	EncryptedShare []byte
}

type ShareConfig struct {
	RequiredShares int
	ShareInfo      map[string]SharePublicDescriptor
}

type ShareCombiner struct {
	config         ShareConfig
	knownShares    map[string]SharePrivateDoc
	combinedSecret []byte
	logger         log.DebugLogger
}
