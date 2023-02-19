package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

const appHost = "localhost:8090"
const keycloakHost = "http://localhost:8080"
const keycloakRealmId = "test-realm"
const keycloakClientId = "test-client"

type UserInfo struct {
	// TODO: User info data: {"sub":"2e1be8d0-853f-4c8c-ae31-086b97a4f60a","email_verified":false,"name":"Jon Snow","preferred_username":"jsnow","given_name":"Jon","family_name":"Snow"}
	Name string `json:"name"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

type OpenIdConfiguration struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`

	AuthorizationEndpointUrl *url.URL
}

type InvalidCodeError struct{}

func (error *InvalidCodeError) Error() string {
	return fmt.Sprintf("InvalidCodeError")
}

var openIdConfig = OpenIdConfiguration{}

func getLoginUrl(redirectUrl *url.URL) string {
	loginUrl := *openIdConfig.AuthorizationEndpointUrl

	loginUrl.RawQuery = url.Values{
		"client_id":     []string{keycloakClientId},
		"response_type": []string{"code"},
		"redirect_uri":  []string{redirectUrl.String()},
		"scope":         []string{"openid"},
	}.Encode()

	return loginUrl.String()
}

func index(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s", req.URL.RequestURI())

	userInfo, err := authenticate(w, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if userInfo == nil {
		return
	}

	fmt.Fprint(w, "<html>")
	fmt.Fprintf(w, "<p>Hello, %s</p>", userInfo.Name)
	fmt.Fprintf(w, "<a href=%q>Log out<a>", openIdConfig.EndSessionEndpoint)
	fmt.Fprint(w, "</html>")
}

func settings(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s", req.URL.RequestURI())

	userInfo, err := authenticate(w, req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Internal server error: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	if userInfo == nil {
		return
	}

	fmt.Fprint(w, "<html>")
	fmt.Fprintf(w, "<p>Settings. User: %s</p>", userInfo.Name)
	fmt.Fprint(w, "</html>")
}

func authenticate(w http.ResponseWriter, req *http.Request) (*UserInfo, error) {
	accessTokenCookie, err := req.Cookie("SSO")

	accessTokenCookieIsSet := err == nil && accessTokenCookie.Value != ""

	// TODO: Comment why.
	redirectQuery := req.URL.Query()
	redirectQuery.Del("code")
	redirectQuery.Del("session_state")

	// TODO: Comment why.
	redirectUrl := &url.URL{
		// TODO: global const or flag.
		Scheme:   "http",
		Host:     req.Host,
		Path:     req.URL.Path,
		RawQuery: redirectQuery.Encode(),
	}

	log.Printf("  redirectUrl: %s", redirectUrl)

	loginUrl := getLoginUrl(redirectUrl)

	if accessTokenCookieIsSet {
		accessToken := accessTokenCookie.Value
		log.Printf("  SSO cookie is set")

		userInfo, err := getUserInfo(accessToken)

		_, invalidToken := err.(*InvalidCodeError)

		if invalidToken {
			http.SetCookie(w, &http.Cookie{Name: "SSO", Value: "", Expires: time.Now()})
			http.Redirect(w, req, loginUrl, http.StatusSeeOther)
			return nil, nil
		} else if err != nil {
			return nil, err
		}

		return userInfo, nil
	}

	log.Printf("  SSO cookie is not set")

	code := req.URL.Query().Get("code")

	if code == "" {
		log.Printf("  code is not set: %q", code)
		http.Redirect(w, req, loginUrl, http.StatusSeeOther)
		return nil, nil
	}

	log.Printf("  code is set")

	accessToken, err := getAccessToken(code, redirectUrl)

	_, invalidCode := err.(*InvalidCodeError)
	if invalidCode {
		log.Printf("  invalid code")
		http.Redirect(w, req, loginUrl, http.StatusSeeOther)
		return nil, nil
	} else if err != nil {
		log.Printf("  error: %s", err)
		return nil, err
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "SSO",
		Value: accessToken,
		// TODO: Set correct value.
		Expires: time.Now().Add(time.Minute),
	})

	log.Printf("Redirecting: %s", redirectUrl)
	http.Redirect(w, req, redirectUrl.String(), http.StatusSeeOther)
	return nil, nil
}

func getAccessToken(code string, redirectUrl *url.URL) (string, error) {
	log.Printf("getAccessToken: %q", code)
	data := url.Values{
		"grant_type":   []string{"authorization_code"},
		"client_id":    []string{keycloakClientId},
		"code":         []string{code},
		"redirect_uri": []string{redirectUrl.String()},
	}

	log.Printf("Get token RPC start: %s", openIdConfig.TokenEndpoint)

	resp, err := http.Post(openIdConfig.TokenEndpoint, "application/x-www-form-urlencoded", bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := &TokenResponse{}

	if err := json.Unmarshal(body, response); err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("  TokenResponse")
		log.Printf("    status: %d", resp.StatusCode)
		log.Printf("    body: %s", body)

		if response.Error == "invalid_grant" {
			return "", &InvalidCodeError{}
		}

		return "", fmt.Errorf(response.Error)
	}

	return response.AccessToken, nil
}

func getUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", openIdConfig.UserInfoEndpoint, nil)
	if err != nil {
		log.Printf("NewRequest error: %s", err.Error())
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		log.Printf("User info request error: %v", err.Error())
		return nil, err
	}

	// TODO: make sure this is invalid_token and not something else?
	if resp.StatusCode == http.StatusUnauthorized {
		// TODO: check error in response?
		return nil, &InvalidCodeError{}
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("User info status code: %d", resp.StatusCode)
	}

	userInfo := &UserInfo{}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("User info response error: %v", err.Error())
		return nil, err
	}

	if err := json.Unmarshal(data, userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

func main() {
	log.Println("Hello world!")

	//localhost:8080/realms/test-realm/.well-known/openid-configuration

	configUrl := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", keycloakHost, keycloakRealmId)

	resp, err := http.Get(configUrl)

	if err != nil {
		log.Fatalf("OpenId configuration error: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("OpenId configuration status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("OpenId configuration body error: %s", err.Error())
	}

	if err := json.Unmarshal(body, &openIdConfig); err != nil {
		log.Fatalf("OpenId configuration json error: %s", err.Error())
	}

	openIdConfig.AuthorizationEndpointUrl, err = url.Parse(openIdConfig.AuthorizationEndpoint)

	if err != nil {
		log.Fatalf("OpenId configuration URL: %s, error: %s", openIdConfig.AuthorizationEndpoint, err.Error())
	}

	log.Printf("OpenId configuration:")
	log.Printf("  authorization_endpoint: %s", openIdConfig.AuthorizationEndpoint)
	log.Printf("  token_endpoint: %s", openIdConfig.TokenEndpoint)
	log.Printf("  userinfo_endpoint: %s", openIdConfig.UserInfoEndpoint)

	http.HandleFunc("/index", index)
	http.HandleFunc("/settings", settings)
	// http.HandleFunc("/loggedin", loggedIn)
	// http.HandleFunc("/index", index)

	err = http.ListenAndServe(":8090", nil)
	if err != nil {
		panic(err)
	}
}
