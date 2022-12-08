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
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

func (c *APIClient) GetCurrentAccountInfo() (*AccountInfoDTO, error) {
	resp := struct {
		Data AccountInfoDTO `json:"data"`
	}{}
	err := c.DoRequest("GET", "/api/v1/account/info", nil, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get account: %w, %#v", err, &resp)
	}
	return &resp.Data, nil
}

func (c *APIClient) ListOrgs() ([]OrgMembershipDTO, error) {
	var orgs []OrgMembershipDTO
	resp := struct {
		Data []OrgMembershipDTO `json:"data"`
	}{}

	err := c.DoRequest("GET", "/api/v1/my/orgs", nil, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to list orgs: %w, %#v", err, &resp)
	}
	for i := range resp.Data {
		orgs = append(orgs, resp.Data[i])
	}
	return orgs, nil
}

func (c *APIClient) UploadToStageByPresignURL(presignURL, fileName string, header map[string]interface{}, displayProgress bool) error {
	fileContent, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	file, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	body := bytes.NewBuffer(fileContent)

	httpReq, err := http.NewRequest("PUT", presignURL, body)
	if err != nil {
		return err
	}
	for k, v := range header {
		httpReq.Header.Set(k, fmt.Sprintf("%v", v))
	}
	httpReq.Header.Set("Content-Length", strconv.FormatInt(int64(len(body.Bytes())), 10))
	httpClient := &http.Client{
		Timeout: time.Second * 60,
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed http do request: %w", err)
	}
	defer httpResp.Body.Close()
	httpRespBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return err
	}
	if httpResp.StatusCode >= 400 {
		return fmt.Errorf("request got bad status: %d req=%s resp=%s", httpResp.StatusCode, body, httpRespBody)
	}
	return nil
}
