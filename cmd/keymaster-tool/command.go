package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/certgen"
	"github.com/Cloud-Foundations/keymaster/lib/cryptoutils"

	"github.com/cviecco/sss-distrib/lib/sssdoc"
)

// /
type GenerateCmd struct {
	KeyType string `help:"Type of key (ed25519|rsa)" default:"ed25519"`
}

// privateKey MUST be an encodable type
func serializePrivateKey(privateKey crypto.Signer, outWriter io.Writer) error {
	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derPrivateKey,
	}
	return pem.Encode(outWriter, privateKeyPEM)
}

func generateNewKeyPair(passPhrase []byte, keyType string, outWriter io.Writer, logger log.DebugLogger) (crypto.PublicKey, error) {
	var privateKey crypto.Signer
	var err error
	switch keyType {
	case "ed25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	case "rsa":
		privateKey, err = rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("bad key type '%s'", keyType)
	}
	var plaintextBuffer bytes.Buffer
	err = serializePrivateKey(privateKey, &plaintextBuffer)
	if err != nil {
		return nil, err
	}

	armoredBytes, err := cryptoutils.PGPArmorEncryptBytes(plaintextBuffer.Bytes(), passPhrase)
	if err != nil {
		return nil, err
	}
	_, err = outWriter.Write(armoredBytes)

	return privateKey.Public(), err
}

func (cmd *GenerateCmd) Run(globals *Globals) error {
	logger := globals.Logger
	passPhrase, err := getPassPhrase(globals.SecretARN, globals.AwsRegion)
	if err != nil {
		return err
	}
	_, err = generateNewKeyPair(passPhrase, cmd.KeyType, os.Stdout, logger)
	if err != nil {
		return err
	}
	return nil
}

// ///////
type GenerateSSSCmd struct {
	SSSFilename     string   `help:"SSSShareDocFilename to write" default:"ssdsoc.json"`
	KeyFilename     string   `help:"Encrypted keyfile to write" default:"caprivate.pem.asc"`
	NumRequiredKeys int      `help:"Num of shares needed to decrypt" required:""`
	PublicKeyPaths  []string `arg:"" name:"path" help:"Files with public keys (one per file)." type:"path"`
	KeyType         string   `help:"Type of key (ed25519|rsa)" default:"ed25519"`
}

const randomStringEntropyBytes = 32

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(rb), nil
}

func (cmd *GenerateSSSCmd) generateAndEncrypt(outDocWriter io.Writer,
	outKeyWriter io.Writer, logger log.DebugLogger) error {
	secret, err := genRandomString()
	if err != nil {
		return err
	}
	recipients, err := sssdoc.LoadMultifiles(cmd.PublicKeyPaths)
	if err != nil {
		return fmt.Errorf("error loading public key files: %w", err)
	}

	_, err = generateNewKeyPair([]byte(secret), cmd.KeyType, outKeyWriter, logger)
	if err != nil {
		return err
	}
	doc, err := sssdoc.GenerateNewDocWithSecret(recipients, cmd.NumRequiredKeys, []byte(secret))

	if err != nil {
		return err
	}
	serialized, err := json.MarshalIndent(*doc, " ", "    ")
	if err != nil {
		return fmt.Errorf("error serializing share doc: %w", err)
	}

	_, err = outDocWriter.Write(serialized)
	return err
}

func (cmd *GenerateSSSCmd) Run(globals *Globals) error {
	logger := globals.Logger
	outDocFile, err := os.OpenFile(cmd.SSSFilename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outDocFile.Close()
	outKeyFile, err := os.OpenFile(cmd.KeyFilename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer outKeyFile.Close()
	return cmd.generateAndEncrypt(outDocFile, outKeyFile, logger)

}

// ////////
type PrintPublicCmd struct {
	InFilename  string `help:"Encrypted file to read" required:""`
	PrintFormat string `help:"Format for output (pem|ssh)" default:"ssh"`
}

func decryptDecodeArmoredPrivateKey(cipherText []byte, passPhrase []byte) (crypto.Signer, error) {
	plaintext, err := cryptoutils.PGPDecryptArmoredBytes(cipherText, passPhrase)
	if err != nil {
		return nil, err
	}
	return certgen.GetSignerFromPEMBytes(plaintext)
}

func goSSHPubToFileString(pub ssh.PublicKey, comment string) (string, error) {
	pubBytes := pub.Marshal()
	encoded := base64.StdEncoding.EncodeToString(pubBytes)
	return pub.Type() + " " + encoded + " " + comment, nil
}

func serializePublic(pubKey crypto.PublicKey, outFormat string, outWriter io.Writer) error {
	switch outFormat {
	case "pem":
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return err
		}
		block := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		}
		return pem.Encode(outWriter, block)
	case "ssh":
		sshPub, err := ssh.NewPublicKey(pubKey)
		if err != nil {
			return err
		}
		sshPubFileString, err := goSSHPubToFileString(sshPub, "keymaster")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(outWriter, "%s\n", sshPubFileString)
		return err

	default:
		return fmt.Errorf("invalid outpur format")
	}
}

func printPublicKey(passPhrase []byte, inFile io.Reader, outFormat string, outWriter io.Writer, logger log.DebugLogger) error {
	cipherText, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}
	signer, err := decryptDecodeArmoredPrivateKey(cipherText, passPhrase)
	if err != nil {
		return err
	}
	pubKey := publicKey(signer)
	if pubKey == nil {
		return fmt.Errorf("Invalid private key type")
	}
	return serializePublic(pubKey, outFormat, outWriter)
}

func (cmd *PrintPublicCmd) Run(globals *Globals) error {
	logger := globals.Logger
	passPhrase, err := getPassPhrase(globals.SecretARN, globals.AwsRegion)
	if err != nil {
		return err
	}
	inFile, err := os.Open(cmd.InFilename) // For read access.
	if err != nil {
		return err
	}
	defer inFile.Close()
	err = printPublicKey(passPhrase, inFile, cmd.PrintFormat, os.Stdout, logger)
	if err != nil {
		return err
	}
	return nil
}
