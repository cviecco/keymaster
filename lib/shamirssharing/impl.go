package shamirssharing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/dsprenkels/sss-go"
)

const SharedKeySizeBytes = 32

func withSecretGenerateShares(secret []byte, numshares int, threshold int) ([][]byte, error) {
	return sss.CreateKeyshares(secret, numshares, threshold)
}

// This generate sss keyhares with dsprenkels's sss go lib
func generateSecretAndSharesv1(numshares int, threshold int) ([][]byte, error) {
	secretKey := make([]byte, SharedKeySizeBytes)
	_, err := rand.Read(secretKey)
	if err != nil {
		return nil, err
	}
	return withSecretGenerateShares(secretKey, numshares, threshold)

}

func withSharesArmoredKeysGenerateConfig(plaintextShares [][]byte,
	armoredPublicKeys [][]byte, threshold int) (*ShareConfig, error) {
	if len(plaintextShares) != len(armoredPublicKeys) {
		return nil, fmt.Errorf("sharesize and armored sizes do not match")
	}
	//return nil, fmt.Errorf("not implemented")

	var rvalue ShareConfig
	rvalue.RequiredShares = threshold
	rvalue.ShareInfo = make(map[string]SharePublicDescriptor)
	for i, plaintextShare := range plaintextShares {
		var privateShare SharePrivateDoc
		privateShare.Version = 1
		privateShare.SecretShare = plaintextShare
		serializedShare, err := json.Marshal(privateShare)

		if err != nil {
			return nil, err
		}
		var descriptor SharePublicDescriptor
		//encodedPlaintext := base64.URLEncoding.EncodeToString(plaintextShare)
		armor, err := helper.EncryptMessageArmored(string(armoredPublicKeys[i]), string(serializedShare))
		if err != nil {
			return nil, err
		}
		descriptor.EncryptedShare = []byte(armor)

		h := sha256.New()
		_, err = h.Write(serializedShare)
		if err != nil {
			return nil, err
		}
		descriptor.Fingerprint = h.Sum(nil)
		base64FP := base64.URLEncoding.EncodeToString(descriptor.Fingerprint)
		rvalue.ShareInfo[base64FP] = descriptor
	}
	return &rvalue, nil

}

func generateShareConfigWithKey(secret []byte, threshold int, armoredPublicKeys [][]byte) (*ShareConfig, error) {
	plaintextShares, err := withSecretGenerateShares(secret, len(armoredPublicKeys), threshold)
	if err != nil {
		return nil, err
	}
	return withSharesArmoredKeysGenerateConfig(plaintextShares, armoredPublicKeys, threshold)
}

func newSecCombiner(config ShareConfig, logger log.DebugLogger) (sc *ShareCombiner) {
	combiner := ShareCombiner{
		config:      config,
		knownShares: make(map[string]SharePrivateDoc),
		logger:      logger,
	}
	return &combiner
}

func (sc *ShareCombiner) AddShareDocToSet(shareDoc []byte) (int, error) {
	// compute FP
	var err error
	h := sha256.New()
	_, err = h.Write(shareDoc)
	base64fp := base64.URLEncoding.EncodeToString(h.Sum(nil))
	_, ok := sc.knownShares[base64fp]
	if ok {
		return 0, fmt.Errorf("Already known Share")
	}
	_, ok = sc.config.ShareInfo[base64fp]
	if !ok {
		return 0, fmt.Errorf("Unkown/invalid share")
	}
	var internalDoc SharePrivateDoc
	err = json.Unmarshal(shareDoc, &internalDoc)
	if err != nil {
		return 0, err
	}
	//sc.logger.Debugf(3, "internalDoc=%+v", internalDoc)
	// TODO:: add validation
	sc.knownShares[base64fp] = internalDoc
	return len(sc.knownShares), nil
}

func (sc *ShareCombiner) combineShare() error {
	if len(sc.knownShares) < sc.config.RequiredShares {
		return fmt.Errorf("not enough shares")
	}
	var shares [][]byte
	for _, shareDoc := range sc.knownShares {
		shares = append(shares, shareDoc.SecretShare)
	}
	//sc.logger.Debugf(3, "shres to restore=%+v", shares)

	// TODO use a switch for the type of restore
	restored, err := sss.CombineKeyshares(shares)
	if err != nil {
		return err
	}
	sc.combinedSecret = restored
	return nil
}
