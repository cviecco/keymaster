package pushtoken

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Cloud-Foundations/golib/pkg/log"
	"github.com/Cloud-Foundations/keymaster/lib/webapi/v0/proto"
)

const vipCheckTimeoutSecs = 180

func debugLogCert(messageSuffix string, cert *x509.Certificate, logger log.DebugLogger) {
	logger.Debugf(2, "%s.issuer=%+v", messageSuffix, cert.Issuer)
	logger.Debugf(2, "%s.subject=%+v", messageSuffix, cert.Subject)
}

func startGenericPush(client *http.Client,
	baseURL string,
	pushType string,
	userAgentString string,
	logger log.DebugLogger) error {

	VIPPushStartURL := baseURL + "/api/v0/" + pushType + "PushStart"

	req, err := http.NewRequest("GET", VIPPushStartURL, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentString)

	pushStartResp, err := client.Do(req)
	if err != nil {
		logger.Printf("got error from pushStart")
		logger.Println(err)
		return err
	}
	defer pushStartResp.Body.Close()

	if pushStartResp.TLS != nil {
		debugLogCert("startGenericPush peeerCerts[0]", pushStartResp.TLS.PeerCertificates[0], logger)
		if pushStartResp.TLS.VerifiedChains != nil {
			debugLogCert("startGenericPush verifiedcerts[0]", pushStartResp.TLS.VerifiedChains[0][0], logger)
		}
	}

	// since we dont care about content we just consume it all.
	io.Copy(ioutil.Discard, pushStartResp.Body)
	if pushStartResp.StatusCode != 200 {
		logger.Printf("got error from vipStart call %s", pushStartResp.Status)
		err := errors.New("bad vip response code")
		return err
	}
	//at this moment we dont actually return json data... so we can just return here
	return nil
}

func checkGenericPollStatus(client *http.Client,
	baseURL string,
	pushType string,
	userAgentString string,
	logger log.DebugLogger) (bool, error) {

	VIPPollCheckURL := baseURL + "/api/v0/" + pushType + "PollCheck"

	req, err := http.NewRequest("GET", VIPPollCheckURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentString)

	pollCheckResp, err := client.Do(req)
	if err != nil {
		logger.Printf("got error from vipPollCheck")
		logger.Println(err)
		return false, err
	}
	defer pollCheckResp.Body.Close()
	// we dont care about content (for now) so consume it all
	io.Copy(ioutil.Discard, pollCheckResp.Body)
	if pollCheckResp.StatusCode != 200 {
		if pollCheckResp.StatusCode == 412 {
			logger.Debugf(1, "got 412 error from vipPollCheck call %s (waiting)", pollCheckResp.Status)
			return false, nil
		}
		logger.Printf("got error from vipPollCheck call %s", pollCheckResp.Status)
		//err := errors.New("bad vip response code")
		return false, nil
	}

	return true, nil
}

func doGenericPushCheck(client *http.Client,
	baseURL string,
	pushType string,
	userAgentString string,
	codeIsDone <-chan bool,
	logger log.DebugLogger,
	errorReturnDuration time.Duration) error {

	err := startGenericPush(client, baseURL, pushType, userAgentString, logger)
	if err != nil {
		logger.Printf("got error from pushStart, will sleep to allow code to be entered")
		logger.Println(err)
		time.Sleep(errorReturnDuration)
		return err
	}
	endTime := time.Now().Add(errorReturnDuration)
	//initial sleep
	for time.Now().Before(endTime) {
		ok, err := checkGenericPollStatus(client, baseURL, pushType, userAgentString, logger)
		if err != nil {
			logger.Printf("got error from vipPollCheck, will sleep to allow code to be entered")
			logger.Println(err)
			time.Sleep(errorReturnDuration)
			return err
		}
		if ok {
			logger.Printf("") //To do a CR
			return nil
		}
		select {
		case codeSuccess := <-codeIsDone:
			if codeSuccess {
				return nil
			}
			continue
		case <-time.After(2 * time.Second):
			logger.Debugf(1, "doGenericPushCheck: timeout on checkGenericPollStatus loop")
		}
	}

	err = errors.New("Vip Push Checked timeout out")
	return err
}

func genericAuthenticateWithToken(
	client *http.Client,
	baseURL string,
	pushType string,
	userAgentString string,
	logger log.DebugLogger) error {
	logger.Debugf(1, "top of genericAuthenticateWithToken")

	// Read VIP token from client

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Enter %s/OTP code (or wait for %s push): ", pushType, pushType)
	otpText, err := reader.ReadString('\n')
	if err != nil {
		logger.Debugf(0, "codeText:  Failure to get string %s", err)
		return err
	}
	otpText = strings.TrimSpace(otpText)
	//fmt.Println(codeText)
	logger.Debugf(1, "codeText:  '%s'", otpText)

	// TODO: add some client side validation that the codeText is actually a six digit
	// integer

	VIPLoginURL := baseURL + "/api/v0/" + pushType + "Auth"
	if pushType == "okta" {
		VIPLoginURL = baseURL + "/api/v0/okta2FAAuth"
	}

	form := url.Values{}
	form.Add("OTP", otpText)
	//form.Add("password", string(password[:]))
	req, err := http.NewRequest("POST", VIPLoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Length", strconv.Itoa(len(form.Encode())))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentString)

	loginResp, err := client.Do(req) //client.Get(targetUrl)
	if err != nil {
		logger.Printf("got error from req")
		logger.Println(err)
		// TODO: differentiate between 400 and 500 errors
		// is OK to fail.. try next
		return err
	}
	defer loginResp.Body.Close()
	if loginResp.StatusCode != 200 {
		logger.Printf("got error from login call %s", loginResp.Status)
		return fmt.Errorf("Failed to authenticate with token")
	}

	loginJSONResponse := proto.LoginResponse{}
	//body := jsonrr.Result().Body
	err = json.NewDecoder(loginResp.Body).Decode(&loginJSONResponse)
	if err != nil {
		return err
	}
	io.Copy(ioutil.Discard, loginResp.Body)

	logger.Debugf(1, "This the login response=%v\n", loginJSONResponse)

	return nil
}

func doGenericTokenPushAuthenticate(
	client *http.Client,
	baseURL string,
	pushType string,
	userAgentString string,
	logger log.DebugLogger) error {

	timeout := time.Duration(time.Duration(vipCheckTimeoutSecs) * time.Second)
	ch := make(chan error, 1)
	doneCh := make(chan bool, 1)
	go func() {
		err := genericAuthenticateWithToken(client, baseURL, pushType, userAgentString, logger)
		if err == nil {
			doneCh <- true
		}
		ch <- err
	}()
	go func() {
		err := doGenericPushCheck(client, baseURL,
			pushType,
			userAgentString,
			doneCh,
			logger, timeout)
		ch <- err

	}()
	select {
	case err := <-ch:
		if err != nil {
			logger.Printf("Problem with %s ='%s'", pushType, err)
			return err
		}
		return nil
	case <-time.After(timeout):
		err := fmt.Errorf("%s timeout", pushType)
		return err
	}
}
