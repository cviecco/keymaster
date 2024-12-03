package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

func TestParseRoleCertGenParams(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")

	//first pass everything OK

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)

	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	//form.Add("password", validPasswordConst)

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	//req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, userErr, err := state.parseRoleCertGenParams(req)
	if err != nil {
		t.Fatal(err)
	}
	if userErr != nil {
		t.Fatal(userErr)
	}

}

func TestRoleRequetingCertGenHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypePassword)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)
	form := url.Values{}
	form.Add("identity", "role1")
	form.Add("requestor_netblock", "127.0.0.1/32")
	form.Add("pubkey", b64public)
	form.Add("target_netblock", "192.168.0.174/32")

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	cookieVal, err := state.setNewAuthCookie(nil, "admin1", AuthTypePassword)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	req.AddCookie(&authCookie)
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr, err := checkRequestHandlerCode(req, state.roleRequetingCertGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

	resp := rr.Result()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	// TODO: check body content is actually pem
}

func TestRefreshRoleRequetingCertGenHandler(t *testing.T) {
	state, passwdFile, err := setupValidRuntimeStateSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(passwdFile.Name()) // clean up

	//
	state.Config.Base.AutomationUsers = append(state.Config.Base.AutomationUsers, "role1")
	state.Config.Base.AutomationAdmins = append(state.Config.Base.AutomationAdmins, "admin1")
	state.Config.Base.AllowedAuthBackendsForCerts = append(state.Config.Base.AllowedAuthBackendsForCerts, proto.AuthTypePassword)
	state.Config.Base.AllowedAuthBackendsForWebUI = []string{"password"}

	userPub, err := getPubKeyFromPem(testUserPEMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	netblock := net.IPNet{
		IP:   net.ParseIP("127.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblock2 := net.IPNet{
		IP:   net.ParseIP("10.0.0.0"),
		Mask: net.CIDRMask(8, 32),
	}
	netblockList := []net.IPNet{netblock, netblock2}

	initialrrParams := roleRequestingCertGenParams{
		Role:               "role1",
		Duration:           time.Hour,
		RequestorNetblocks: netblockList,
		UserPub:            userPub,
	}
	_, rrcert, err := state.withParamsGenegneratRoleRequetingCert(&initialrrParams)
	if err != nil {
		t.Fatal(err)
	}

	userPemBlock, _ := pem.Decode([]byte(testUserPEMPublicKey))
	b64public := base64.RawURLEncoding.EncodeToString(userPemBlock.Bytes)
	form := url.Values{}
	form.Add("pubkey", b64public)

	req, err := http.NewRequest("POST", getRoleRequestingPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:12345"
	var fakePeerCertificates []*x509.Certificate
	var fakeVerifiedChains [][]*x509.Certificate
	fakePeerCertificates = append(fakePeerCertificates, rrcert)
	fakeVerifiedChains = append(fakeVerifiedChains, fakePeerCertificates)
	connectionState := &tls.ConnectionState{
		VerifiedChains:   fakeVerifiedChains,
		PeerCertificates: fakePeerCertificates}
	req.TLS = connectionState

	//TODO add fail value
	_, err = checkRequestHandlerCode(req, state.refreshRoleRequetingCertGenHandler, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}

}
