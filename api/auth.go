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
	dc "github.com/databendcloud/databend-go"
	"github.com/pkg/errors"

	"github.com/databendcloud/bendsql/internal/config"
)

func (c *APIClient) Login() error {
	req := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    c.UserEmail,
		Password: c.Password,
	}
	path := "/api/v1/account/sign-in"
	reply := struct {
		Data struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
		} `json:"data,omitempty"`
	}{}
	err := c.DoRequest("POST", path, nil, &req, &reply)
	var apiErr dc.APIError
	if errors.As(err, &apiErr) && dc.IsAuthFailed(err) {
		apiErr.Hint = "" // shows the server replied message if auth Err
		return apiErr
	} else if err != nil {
		return err
	}
	c.resetTokens(reply.Data.AccessToken, reply.Data.RefreshToken)
	return nil
}

func (c *APIClient) resetTokens(accessToken string, refreshToken string) {
	c.AccessToken = accessToken
	c.RefreshToken = refreshToken
}

// RefreshTokens every api cmd
func (c *APIClient) RefreshTokens() error {
	req := struct {
		RefreshToken string `json:"refreshToken"`
	}{
		RefreshToken: c.RefreshToken,
	}
	resp := struct {
		Data struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
		} `json:"data"`
	}{}
	path := "/api/v1/account/renew-token"
	err := c.DoRequest("POST", path, nil, &req, &resp)
	if err != nil {
		return err
	}
	c.resetTokens(resp.Data.AccessToken, resp.Data.RefreshToken)
	err = config.RenewTokens(c.AccessToken, c.RefreshToken)
	if err != nil {
		return err
	}
	return nil
}
