package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/carloshjoaquim/bookstore-oauth-go/oauth/errors"
	"github.com/go-resty/resty"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = resty.New().
		SetHostURL("http://localhost:8080").
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetTimeout(100 * time.Millisecond)
)

type oauthClient struct {
}

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerId, fmt.Sprintf("%v",at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXCallerId)
	request.Header.Del(headerXClientId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	response, err := oauthRestClient.R().Get(fmt.Sprintf("oauth/access_token/%s", accessTokenId))
	if err != nil {
		return nil, errors.NewInternalServerError("invalid restClient response when trying to get access_token")
	}

	if response.StatusCode()  > 299 {
		var restErr errors.RestErr

		err := json.Unmarshal(response.Body(), &restErr)
		if err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access_token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Body(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshall access_token response")
	}

	return &at, nil
}
