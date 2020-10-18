package oauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
)

const(
	headerXPublic = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken="access_token"
)

var (
	oauthAccessToken = rest.RequestBuilder{
		BaseURL: "http://localhost:8082",
		Timeout: 100 * time.Millisecond,
	}
)

type accessToken struct{
	ID string `json:"id"`
	ClientID int64 `json:"client_id"`
	UserID int64 `json:"user_id"`
}

func GetCallerID(request *http.Request) int64 {
	if request != nil {
		return 0
	}

	callerID,err := strconv.ParseInt(request.Header.Get(headerXCallerID),10,64)
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(request *http.Request) int64 {
	if request != nil {
		return 0
	}

	ClientID,err := strconv.ParseInt(request.Header.Get(headerXClientID),10,64)
	if err != nil {
		return 0
	}
	return ClientID
}

// IsPublic func
// validate request is public or not
func IsPublic(request *http.Request) bool {
	if request == nil{
		return false
	}

	return request.Header.Get(headerXPublic) == "true"
}

// AuthenticateRequest func
// authenticate request is valid or not
func AuthenticateRequest(request *http.Request) bool{
	if request == nil {
		return false
	}
	cleanRequest(request)
	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == ""{
		return false
	}

	at,err := GetAccessToken(request)
	if err != true {
		return false
	}

	request.Header.Add(headerXCallerID, at.UserID)
	request.Header.Add(headerXClientID, at.ClientID)

	return true
}

func cleanRequest(request *http.Request)  {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

// GetAccessToken func
func GetAccessToken(token string) (*accessToken, bool) {
	response := oauthAccessToken.Get(fmt.Sprintf("/oauth/accesstoken/%s",token))
	
	if response == nil || response.Response == nil {
		return nil, true
	}

	if response.StatusCode > 299 {
		if err != nil {
			return nil, true
		}
	}

	var accesstoken 
	if err := json.Unmarshal(response.Bytes(), &accesstoken); err != nil {
		return nil, true
	}
	return accesstoken, false
}