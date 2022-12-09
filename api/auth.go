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
	"net/http"
	"time"

	dc "github.com/databendcloud/databend-go"
	"github.com/pkg/errors"

	"github.com/databendcloud/bendsql/internal/config"
)

func (c *Client) DoAuthRequest(method, path string, headers http.Header, req interface{}, resp interface{}) error {
	if headers != nil {
		headers = headers.Clone()
	} else {
		headers = http.Header{}
	}
	return c.request(method, path, headers, req, resp)
}

func (c *Client) Login(email, password string) error {
	req := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    email,
		Password: password,
	}
	path := "/api/v1/account/sign-in"
	resp := struct {
		Data struct {
			AccessToken  string    `json:"accessToken"`
			RefreshToken string    `json:"refreshToken"`
			ExpiresAt    time.Time `json:"expiresAt"`
		} `json:"data,omitempty"`
	}{}
	err := c.DoAuthRequest("POST", path, nil, &req, &resp)
	var apiErr dc.APIError
	if errors.As(err, &apiErr) && dc.IsAuthFailed(err) {
		apiErr.Hint = "" // shows the server replied message if auth Err
		return apiErr
	} else if err != nil {
		return errors.Wrap(err, "failed to login")
	}
	token := &config.Token{
		AccessToken:  resp.Data.AccessToken,
		RefreshToken: resp.Data.RefreshToken,
		ExpiresAt:    resp.Data.ExpiresAt,
	}

	// NOTE: should not write config here, in login command instead
	c.cfg.Token = token
	return nil
}

func (c *Client) RefreshToken() error {
	req := struct {
		RefreshToken string `json:"refreshToken"`
	}{
		RefreshToken: c.cfg.Token.RefreshToken,
	}
	resp := struct {
		Data struct {
			AccessToken  string    `json:"accessToken"`
			RefreshToken string    `json:"refreshToken"`
			ExpiresAt    time.Time `json:"expiresAt"`
		} `json:"data"`
	}{}
	path := "/api/v1/account/renew-token"
	err := c.DoAuthRequest("POST", path, nil, &req, &resp)
	if err != nil {
		return errors.Wrap(err, "failed to refresh tokens")
	}
	token := &config.Token{
		AccessToken:  resp.Data.AccessToken,
		RefreshToken: resp.Data.RefreshToken,
		ExpiresAt:    resp.Data.ExpiresAt,
	}
	c.cfg.Token = token
	err = c.WriteConfig()
	if err != nil {
		return errors.Wrap(err, "failed to write config")
	}
	return nil
}
