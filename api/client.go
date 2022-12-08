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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/databendcloud/bendsql/internal/config"
	dc "github.com/databendcloud/databend-go"
	"github.com/pkg/errors"
)

type APIClient struct {
	UserEmail        string
	Password         string
	AccessToken      string
	RefreshToken     string
	CurrentOrgSlug   string
	CurrentWarehouse string
	Endpoint         string
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
	accessToken, refreshToken, err := config.GetAuthToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get auth token")
	}
	client := &APIClient{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		CurrentOrgSlug:   config.GetOrg(),
		CurrentWarehouse: config.GetWarehouse(),
		Endpoint:         config.GetEndpoint(),
	}
	return client, nil
}

func (c *APIClient) DoRequest(method, path string, headers http.Header, req interface{}, resp interface{}) error {
	var err error

	reqBody := []byte{}
	if req != nil {
		reqBody, err = json.Marshal(req)
		if err != nil {
			panic(err)
		}
	}

	url, err := c.makeURL(path)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return err
	}

	if headers != nil {
		httpReq.Header = headers.Clone()
	}
	httpReq.Header.Set(contentType, jsonContentType)
	httpReq.Header.Set(accept, jsonContentType)
	if len(c.AccessToken) > 0 {
		httpReq.Header.Set(authorization, "Bearer "+c.AccessToken)
	}

	httpClient := &http.Client{}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed http do request: %w", err)
	}
	defer httpResp.Body.Close()

	httpRespBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("io read error: %w", err)
	}

	if httpResp.StatusCode == http.StatusUnauthorized {
		return dc.NewAPIError("please use `bendsql auth login` to login your account.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 500 {
		return dc.NewAPIError("please retry again later.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 400 {
		return dc.NewAPIError("please check your arguments.", httpResp.StatusCode, httpRespBody)
	}

	if resp != nil {
		if err := json.Unmarshal(httpRespBody, &resp); err != nil {
			return err
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
		return "", err
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
	cfg.AccessToken = c.AccessToken

	dsn = cfg.FormatDSN()
	return
}
