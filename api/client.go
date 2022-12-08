// Copyright 2022 Datafuse Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/databendcloud/bendsql/internal/config"
	dc "github.com/databendcloud/databend-go"
	"github.com/pkg/errors"
)

type APIClient struct {
	CurrentOrgSlug   string
	CurrentWarehouse string
	Endpoint         string

	Token *config.Token
}

const (
	accept          = "Accept"
	authorization   = "Authorization"
	contentType     = "Content-Type"
	jsonContentType = "application/json; charset=utf-8"
	timeZone        = "Time-Zone"
	userAgent       = "User-Agent"

	EndpointGlobal = "https://app.databend.com"
	EndpointCN     = "https://app.databend.cn"
)

func NewApiClient() (*APIClient, error) {
	token, err := config.GetToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get auth token")
	}
	client := &APIClient{
		CurrentOrgSlug:   config.GetOrg(),
		CurrentWarehouse: config.GetWarehouse(),
		Endpoint:         config.GetEndpoint(),
		Token:            token,
	}
	return client, nil
}

func (c *APIClient) DoRequest(method, path string, headers http.Header, req interface{}, resp interface{}) error {
	if c.Token == nil {
		return errors.New("please use `bendsql login` to login your account first")
	}
	if c.Token.ExpiresAt.Before(time.Now()) {
		err := c.RefreshTokenIfNeeded()
		if err != nil {
			return errors.Wrap(err, "failed to refresh token")
		}
	}
	if headers != nil {
		headers = headers.Clone()
	} else {
		headers = http.Header{}
	}
	headers.Set(authorization, "Bearer "+c.Token.AccessToken)
	return c.request(method, path, headers, req, resp)
}

func (c *APIClient) request(method, path string, headers http.Header, req interface{}, resp interface{}) error {
	var err error

	reqBody := []byte{}
	if req != nil {
		reqBody, err = json.Marshal(req)
		if err != nil {
			return errors.Wrap(err, "failed to marshal request body")
		}
	}

	url, err := c.makeURL(path)
	if err != nil {
		return errors.Wrap(err, "failed to make url")
	}
	httpReq, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return errors.Wrap(err, "failed to create http request")
	}

	httpReq.Header = headers
	httpReq.Header.Set(contentType, jsonContentType)
	httpReq.Header.Set(accept, jsonContentType)

	httpClient := &http.Client{}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return errors.Wrap(err, "http request error")
	}
	defer httpResp.Body.Close()

	httpRespBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read http response body")
	}

	if httpResp.StatusCode == http.StatusUnauthorized {
		return dc.NewAPIError("please use `bendsql login` to login your account.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 500 {
		return dc.NewAPIError("please retry again later.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 400 {
		return dc.NewAPIError("please check your arguments.", httpResp.StatusCode, httpRespBody)
	}

	if resp != nil {
		if err := json.Unmarshal(httpRespBody, &resp); err != nil {
			return errors.Wrap(err, "failed to unmarshal http response body")
		}
	}

	return nil
}

func (c *APIClient) makeURL(path string) (string, error) {
	apiEndpoint := os.Getenv("BENDSQL_API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = c.Endpoint
	}
	if apiEndpoint == "" {
		apiEndpoint = EndpointGlobal
	}
	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse api endpoint")
	}
	u.Path = path
	return u.String(), nil
}

func (c *APIClient) GetCloudDSN() (dsn string, err error) {
	cfg := dc.NewConfig()
	if strings.HasPrefix(c.Endpoint, "http://") {
		cfg.SSLMode = "disable"
	}
	cfg.Host = config.GetGateway()
	cfg.Tenant = config.GetTenant()
	cfg.Warehouse = c.CurrentWarehouse
	cfg.AccessToken = c.Token.AccessToken

	dsn = cfg.FormatDSN()
	return
}
