package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// Client ID
	oauthClientId = ""

	deviceCodeUrl  = "https://github.com/login/device/code"
	accessTokenUrl = "https://github.com/login/oauth/access_token"

	// https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps
	// empty value means "read-only access to public information"
	scope = ""

	// fixed value
	grantType = "urn:ietf:params:oauth:grant-type:device_code"
)

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
}

func post(url string, params url.Values) ([]byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	// https://docs.github.com/en/developers/apps/building-oauth-apps/authorizing-oauth-apps#response-1
	req.Header.Set("Accept", "application/json")

	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

func postDeviceCode() (*deviceCodeResponse, error) {
	values := url.Values{}
	values.Add("client_id", oauthClientId)
	values.Add("scope", scope)

	body, err := post(deviceCodeUrl, values)
	if err != nil {
		return nil, err
	}

	res := &deviceCodeResponse{}
	err = json.Unmarshal(body, res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

type accessTokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorUri         string `json:"error_uri"`
}

func postAccessToken(deviceCode string) (*accessTokenResponse, *accessTokenErrorResponse, error) {
	values := url.Values{}
	values.Add("client_id", oauthClientId)
	values.Add("device_code", deviceCode)
	values.Add("grant_type", grantType)

	body, err := post(accessTokenUrl, values)
	if err != nil {
		return nil, nil, err
	}

	res := &accessTokenResponse{}
	err = json.Unmarshal(body, res)
	if err == nil && res.AccessToken != "" {
		return res, nil, nil
	}

	errRes := &accessTokenErrorResponse{}
	err = json.Unmarshal(body, errRes)
	if err == nil && errRes.Error != "" {
		return nil, errRes, nil
	}

	return nil, nil, err
}

func pollAccessToken(deviceCode string, interval time.Duration, expiresAt time.Time) (*accessTokenResponse, error) {
	for {
		time.Sleep(interval)
		if time.Now().After(expiresAt) {
			return nil, errors.New("code is already expired")
		}

		acResp, acErrResp, err := postAccessToken(deviceCode)
		if err != nil {
			return nil, err
		}

		if acErrResp != nil {
			// https://docs.github.com/ja/developers/apps/building-oauth-apps/authorizing-oauth-apps#error-codes-for-the-device-flow
			if acErrResp.Error == "authorization_pending" {
				continue
			}
			if acErrResp.Error == "slow_down" {
				interval *= 2
				continue
			}
			if acErrResp.Error != "" {
				err := fmt.Errorf("%s %s %s", acErrResp.Error, acErrResp.ErrorDescription, acErrResp.ErrorUri)
				return nil, err
			}
		}

		return acResp, nil
	}
}

func run(args []string) error {
	// https://docs.github.com/ja/developers/apps/building-oauth-apps/authorizing-oauth-apps#device-flow

	// Step 1: App requests the device and user verification codes from GitHub
	deviceCodeRequestTime := time.Now()
	dcResp, err := postDeviceCode()
	if err != nil {
		return err
	}

	// Step 2: Prompt the user to enter the user code in a browser
	fmt.Printf("Open %s in your browser and enter this code:\n", dcResp.VerificationURI)
	fmt.Println(dcResp.UserCode)
	if err != nil {
		return err
	}

	// Step 3: App polls GitHub to check if the user authorized the device
	interval := time.Duration(dcResp.Interval+1) * time.Second
	expiresAt := deviceCodeRequestTime.Add(time.Duration(dcResp.ExpiresIn) * time.Second)
	acResp, err := pollAccessToken(dcResp.DeviceCode, interval, expiresAt)
	if err != nil {
		return err
	}
	fmt.Println("access token:", acResp.AccessToken)

	return nil
}

func main() {
	if err := run(os.Args); err != nil {
		panic(err)
	}
}
