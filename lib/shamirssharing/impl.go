package shamirssharing

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/helper"
	"github.com/dsprenkels/sss-go"
)

const SharedKeySizeBytes = 32

func func1() {
	fmt.Println("vim-go")
}

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

func generateShareConfigWithKey(secret []byte, threshold int, armoredPublicKeys [][]byte) (*ShareConfig, error) {
	plaintextShares, err := withSecretGenerateShares(secret, len(armoredPublicKeys), threshold)
	if err != nil {
		return nil, err
	}

	var rvalue ShareConfig
	rvalue.RequiredShares = threshold
	rvalue.ShareInfo = make(map[string]SharePublicDescriptor)

	//var descriptorSet []SharePublicDescriptor
	//var encryptedBytes [][]byte

	// TODO: actually find the keyID
	for i, plaintextShare := range plaintextShares {
		var privateShare SharePrivateDoc
		privateShare.Version = 1
		privateShare.SecretShare = plaintextShare
		encodedPrivate, err := json.Marshal(privateShare)
		if err != nil {
			return nil, err
		}
		var descriptor SharePublicDescriptor
		//encodedPlaintext := base64.URLEncoding.EncodeToString(plaintextShare)
		armor, err := helper.EncryptMessageArmored(string(armoredPublicKeys[i]), string(encodedPrivate))
		if err != nil {
			return nil, err
		}
		descriptor.EncryptedShare = []byte(armor)

		h := sha256.New()
		_, err = h.Write(encodedPrivate)
		if err != nil {
			return nil, err
		}
		descriptor.Fingerprint = h.Sum(nil)
		base64FP := base64.URLEncoding.EncodeToString(descriptor.Fingerprint)
		rvalue.ShareInfo[base64FP] = descriptor
	}
	return &rvalue, nil
}

func newSecCombiner(config ShareConfig) (sc *ShareCombiner) {
	combiner := ShareCombiner{
		config:      config,
		knownShares: make(map[string]SharePrivateDoc),
	}
	return &combiner
}

func (sc *ShareCombiner) AddShareDocToSet(shareDoc []byte) (int, error) {
	// compute FP
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
	err := json.Unmarshal(shareDoc, &internalDoc)
	if err != nil {
		return 0, err
	}
	// TODO:: add validation
	sc.knownShares[base64fp] = internalDoc
	return len(sc.knownShares), nil
}

func (sc *ShareCombiner) combineShare() ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
