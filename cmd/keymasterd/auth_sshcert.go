package main

import (
	"encoding/json"
	"net/http"

	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
	"golang.org/x/crypto/ssh"
)

// Thus function can only be called after all known keymaster public keys
// have been loaded, that is after the server is ready
func (state *RuntimeState) initialzeSelfSSHCertAuthenticator() error {

	// build ssh pubkey list
	var sshTrustedKeys []string
	for _, pubkey := range state.KeymasterPublicKeys {
		sshPubkey, err := ssh.NewPublicKey(pubkey)
		if err != nil {
			return err
		}
		authorizedKey := ssh.MarshalAuthorizedKey(sshPubkey)
		sshTrustedKeys = append(sshTrustedKeys, string(authorizedKey))
	}
	return state.sshCertAuthenticator.UnsafeUpdateCaKeys(sshTrustedKeys)
}

// CreateChallengeHandler is an example of how to write a handler for
// the path to create the challenge
func (s *RuntimeState) CreateSSHCertAuthChallengeHandler(w http.ResponseWriter, r *http.Request) {
	err := s.sshCertAuthenticator.CreateChallengeHandler(w, r)
	if err != nil {
		// we are assuming bad request
		s.logger.Debugf(1,
			"CreateSSHCertAuthChallengeHandler: there was an err computing challenge: %s", err)
		s.writeFailureResponse(w, r, http.StatusBadRequest, "Invalid Operation")
		return
	}
}

func (s *RuntimeState) LoginWithChallengeHandler(w http.ResponseWriter, r *http.Request) {
	username, maxAge, userErrString, err := s.sshCertAuthenticator.LoginWithChallenge(r)
	if err != nil {
		s.logger.Printf("error=%s", err)
		errorCode := http.StatusBadRequest
		if userErrString == "" {
			errorCode = http.StatusInternalServerError
		}
		//http.Error(w, userErrString, errorCode)
		s.writeFailureResponse(w, r, errorCode, userErrString)
		return
	}
	// TODO: make the maxAge the smaller of maxAge and now + 60s
	// Make new auth cookie
	_, err = s.setNewAuthCookieWithExpiration(w, username, AuthTypeKeymasterSSHCert, maxAge)
	if err != nil {
		s.writeFailureResponse(w, r, http.StatusInternalServerError,
			"error internal")
		s.logger.Println(err)
		return
	}

	returnAcceptType := getPreferredAcceptType(r)
	// TODO: The cert backend should depend also on per user preferences.
	loginResponse := proto.LoginResponse{Message: "success"}
	switch returnAcceptType {
	case "text/html":
		loginDestination := getLoginDestination(r)
		eventNotifier.PublishWebLoginEvent(username)
		s.logger.Debugf(0, "redirecting to: %s\n", loginDestination)
		http.Redirect(w, r, loginDestination, 302)
	default:
		// RODO needs eventnotifier?
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(loginResponse)
	}

}
