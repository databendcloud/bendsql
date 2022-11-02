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

	"github.com/databendcloud/bendsql/api/apierrors"
	"github.com/databendcloud/bendsql/internal/config"
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

func NewApiClient() *APIClient {
	accessToken, refreshToken := config.GetAuthToken()
	return &APIClient{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		CurrentOrgSlug:   config.GetOrg(),
		CurrentWarehouse: config.GetWarehouse(),
		Endpoint:         config.GetEndpoint(),
	}
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

	url := c.makeURL(path, nil)
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
		return apierrors.New("please use `bendsql auth login` to login your account.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 500 {
		return apierrors.New("please retry again later.", httpResp.StatusCode, httpRespBody)
	} else if httpResp.StatusCode >= 400 {
		return apierrors.New("please check your arguments.", httpResp.StatusCode, httpRespBody)
	}

	if resp != nil {
		if err := json.Unmarshal(httpRespBody, &resp); err != nil {
			return err
		}
	}

	return nil
}

func (c *APIClient) makeURL(path string, args map[string]string) string {
	apiEndpoint := os.Getenv("BENDSQL_API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = c.Endpoint
	}
	if apiEndpoint == "" {
		apiEndpoint = EndpointGlobal
	}
	u := &url.URL{
		Scheme: "https",
		Host:   apiEndpoint,
		Path:   path,
	}
	if args != nil {
		q := u.Query()
		for k, v := range args {
			q.Add(k, v)
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}
