package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/emadghaffari/res_errors/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthAccessToken = rest.RequestBuilder{
		BaseURL: "http://localhost:8082",
		Timeout: 100 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	UserID   string `json:"user_id"`
}

// GetCallerID func
func GetCallerID(request *http.Request) int64 {
	if request != nil {
		return 0
	}

	callerID, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

// GetClientID func
func GetClientID(request *http.Request) int64 {
	if request != nil {
		return 0
	}

	ClientID, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return ClientID
}

// IsPublic func
// validate request is public or not
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

// AuthenticateRequest func
// authenticate request is valid or not
func AuthenticateRequest(request *http.Request) *errors.ResError {
	if request == nil {
		return errors.HandlerBadRequest("request is null")
	}
	cleanRequest(request)
	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == "" {
		return errors.HandlerBadRequest("accessToken is null")
	}

	at, err := GetAccessToken(accessToken)
	if err != nil {
		return err
	}

	request.Header.Add(headerXCallerID, at.UserID)
	request.Header.Add(headerXClientID, at.ClientID)

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

// GetAccessToken func
func GetAccessToken(token string) (*accessToken, *errors.ResError) {
	response := oauthAccessToken.Get(fmt.Sprintf("/oauth/access_token/%s", token))

	if response == nil || response.Response == nil {
		return nil, errors.HandlerBadRequest("request is null")
	}

	if response.StatusCode > 299 {
		return nil, errors.HandlerBadRequest(fmt.Sprintf("response is invalid %v", response))
	}

	var atc accessToken
	if err := json.Unmarshal(response.Bytes(), &atc); err != nil {
		return nil, errors.HandlerBadRequest(fmt.Sprintf("system cant unmarshal data: %v", err))
	}
	return &atc, nil
}
