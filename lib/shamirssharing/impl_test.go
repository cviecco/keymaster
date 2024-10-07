package shamirssharing

import (
	"encoding/json"
	"testing"

	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
	"github.com/dsprenkels/sss-go"
)

// Private keys protected with password: "password"
// user1@example.com
const user1Private = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZu74RhYJKwYBBAHaRw8BAQdAXOY9fGDuIzVDWi5u6J3rtEWV7TJ1PZuSaaYh
EkG2POH+BwMC/rciAmWjKNf/F2M8zSx9h+rFNx1istFoiwJmu+qDzMGS9ErfXF2L
igwZGqpcWkwXftnnaNMI0sIX4hh2efVlDc5Z5XiePQ37lA/8kV6wy7QZdXNlcjEg
PHVzZXIxQGV4YW1wbGUuY29tPoiZBBMWCgBBFiEEdQwjz0fr1EAkCm6Aa0XiwW3q
KXgFAmbu+EYCGwMFCQWjmoAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ
a0XiwW3qKXgCQwEAinXJ010xPAYr9LiaIGiGkXVyPUII7zRKoDWbfUPXfkoBAMZe
vH6crPw7QncJTRkGnw1cIe29CejGRVyjEabRNJIBnIsEZu74RhIKKwYBBAGXVQEF
AQEHQPNCHOJtzb1rNLcFpiEnnZ0s4hvERONfYovOb9CoNnYTAwEIB/4HAwL/Zooc
WNd8Qf/3iQaJ7XkcnUjTAQWvZzXKmC5iibEHoa/XB0zs5+WtnKihYIHbdDjxrQ2h
0j4hf5rSdx8ov7syk7pw2D2IkOI/4S+SFflaiH4EGBYKACYWIQR1DCPPR+vUQCQK
boBrReLBbeopeAUCZu74RgIbDAUJBaOagAAKCRBrReLBbeopeAb7AQDcY5rJyyzG
vSRSMOe5rjknzSAFj+iEhR+FNmAhxWbz+QD+J+5euhD0K09077nKq5+WfDV7NTHX
vMGlALiHuudp6gs=
=U2eS
-----END PGP PRIVATE KEY BLOCK-----`

// cviecco@Camilos-MacBook-Pro-2 shamirssharing % gpg --output user1-public.pgp --armor --export user1@example.com
// cviecco@Camilos-MacBook-Pro-2 shamirssharing % cat user1-public.pgp
const user1Public = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZu74RhYJKwYBBAHaRw8BAQdAXOY9fGDuIzVDWi5u6J3rtEWV7TJ1PZuSaaYh
EkG2POG0GXVzZXIxIDx1c2VyMUBleGFtcGxlLmNvbT6ImQQTFgoAQRYhBHUMI89H
69RAJApugGtF4sFt6il4BQJm7vhGAhsDBQkFo5qABQsJCAcCAiICBhUKCQgLAgQW
AgMBAh4HAheAAAoJEGtF4sFt6il4AkMBAIp1ydNdMTwGK/S4miBohpF1cj1CCO80
SqA1m31D135KAQDGXrx+nKz8O0J3CU0ZBp8NXCHtvQnoxkVcoxGm0TSSAbg4BGbu
+EYSCisGAQQBl1UBBQEBB0DzQhzibc29azS3BaYhJ52dLOIbxETjX2KLzm/QqDZ2
EwMBCAeIfgQYFgoAJhYhBHUMI89H69RAJApugGtF4sFt6il4BQJm7vhGAhsMBQkF
o5qAAAoJEGtF4sFt6il4BvsBANxjmsnLLMa9JFIw57muOSfNIAWP6ISFH4U2YCHF
ZvP5AP4n7l66EPQrT3Tvucqrn5Z8NXs1Mde8waUAuIe652nqCw==
=l1nk
-----END PGP PUBLIC KEY BLOCK-----`

// gpg --output user2-private.pgp --armor --export-secret-key user2@example.com
const user2Private = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZu74ZRYJKwYBBAHaRw8BAQdAG3Js21RJTxW1Jxfg1+BakSyQFaS0hoPimFkp
Hjfzcdb+BwMCumUc3Gcsb13/ou90wV85zAKJTQqPEROGvL53cOpic0OYinFl0db5
5yHbNKUgu9+p01OChjfHdZZmeBWLf7tuP30rEc3QqbYRoN+bUwCZlrQZdXNlcjIg
PHVzZXIyQGV4YW1wbGUuY29tPoiZBBMWCgBBFiEEroJVzkIde4WGiD+9shuoA6rE
ed0FAmbu+GUCGwMFCQWjmoAFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ
shuoA6rEed3MmgEAzN1HQ/wpwG+yITlwkI2CAEEyiruqYO0k7PY7dj3z6Z0A/2P/
vCad9DbMCjhY8tySUMKAvcsh1z5W5d4LZJ+B4S8JnIsEZu74ZRIKKwYBBAGXVQEF
AQEHQN5kHNZMZwtf1FhtucbHoda6evkbpJh5s0OqC1OLXc4XAwEIB/4HAwIy/bLb
Nhn68/82+/EmVIGsLrzD4Ft+AvXWjnm7glywQkxyRQ5mlbn/c6r5wIgSl10mgXPD
1mlPojiYVpkBDPLyvJCeO+RnyLz2p6c3w30YiH4EGBYKACYWIQSuglXOQh17hYaI
P72yG6gDqsR53QUCZu74ZQIbDAUJBaOagAAKCRCyG6gDqsR53V+tAQCWyfR5B09f
EJPeibZKhx5HyoH0r9MPG8lZbVzL89XJ/gEA6AOdKh+YMpt7SxcvkguEcxkPqw8a
GbXOYHfqu7/TOgo=
=Op74
-----END PGP PRIVATE KEY BLOCK-----`

// cviecco@Camilos-MacBook-Pro-2 shamirssharing % gpg --output user2-public.pgp --armor --export user2@example.com
// viecco@Camilos-MacBook-Pro-2 shamirssharing % cat user2-public.pgp
const user2Public = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZu74ZRYJKwYBBAHaRw8BAQdAG3Js21RJTxW1Jxfg1+BakSyQFaS0hoPimFkp
Hjfzcda0GXVzZXIyIDx1c2VyMkBleGFtcGxlLmNvbT6ImQQTFgoAQRYhBK6CVc5C
HXuFhog/vbIbqAOqxHndBQJm7vhlAhsDBQkFo5qABQsJCAcCAiICBhUKCQgLAgQW
AgMBAh4HAheAAAoJELIbqAOqxHndzJoBAMzdR0P8KcBvsiE5cJCNggBBMoq7qmDt
JOz2O3Y98+mdAP9j/7wmnfQ2zAo4WPLcklDCgL3LIdc+VuXeC2SfgeEvCbg4BGbu
+GUSCisGAQQBl1UBBQEBB0DeZBzWTGcLX9RYbbnGx6HWunr5G6SYebNDqgtTi13O
FwMBCAeIfgQYFgoAJhYhBK6CVc5CHXuFhog/vbIbqAOqxHndBQJm7vhlAhsMBQkF
o5qAAAoJELIbqAOqxHndX60BAJbJ9HkHT18Qk96JtkqHHkfKgfSv0w8byVltXMvz
1cn+AQDoA50qH5gym3tLFy+SC4RzGQ+rDxoZtc5gd+q7v9M6Cg==
=B4GI
-----END PGP PUBLIC KEY BLOCK-----`

func TestMinimalGenCombine(t *testing.T) {
	//secret := "01234567890123456789012345678901"
	data := make([]byte, 32)
	for i, _ := range data {
		data[i] = 42
	}
	threshold := 2
	shares, err := withSecretGenerateShares(data, 2, threshold)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := sss.CombineKeyshares(shares)
	if err != nil {
		t.Fatal(err)
	}
	//t.Logf("restored %s", string(restored))

	if string(restored) != string(data) {
		t.Fatal("restore failed")
	}

}

func TestInternalRoundTripMinimal(t *testing.T) {
	armoredPubKeys := [][]byte{
		[]byte(user1Public),
		[]byte(user2Public),
	}
	// secret MUST be 32bytes in len
	secret := "01234567890123456789012345678901"
	threshold := 2
	plaintextShares, err := withSecretGenerateShares([]byte(secret), len(armoredPubKeys), threshold)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintextShares=+%v", plaintextShares)
	_, err = sss.CombineKeyshares(plaintextShares)
	if err != nil {
		t.Fatal(err)
	}

	shareConfig, err := withSharesArmoredKeysGenerateConfig(plaintextShares, armoredPubKeys, threshold)
	if err != nil {
		t.Fatal(err)
	}
	combiner := newSecCombiner(*shareConfig, testlogger.New(t))

	for _, share := range plaintextShares {
		var privateShare SharePrivateDoc
		privateShare.Version = 1
		privateShare.SecretShare = share
		serializedShare, err := json.Marshal(privateShare)
		if err != nil {
			t.Fatal(err)
		}
		_, err = combiner.AddShareDocToSet(serializedShare)
		if err != nil {
			t.Fatal(err)
		}
	}

	err = combiner.combineShare()
	if err != nil {
		t.Fatal(err)
	}
}

func TestInternalFullIncomplete(t *testing.T) {
	armoredPubKeys := [][]byte{
		[]byte(user1Public),
		[]byte(user2Public),
	}
	// secret MUST be 32bytes in len
	secret := "01234567890123456789012345678901"
	threshold := 2
	plaintextShares, err := withSecretGenerateShares([]byte(secret), len(armoredPubKeys), threshold)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("plaintextShares=+%v", plaintextShares)
	_, err = sss.CombineKeyshares(plaintextShares)
	if err != nil {
		t.Fatal(err)
	}
}
