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
	"strings"
	"time"

	"github.com/avast/retry-go"
	"github.com/pkg/errors"

	"github.com/databendcloud/bendsql/internal/config"
	dc "github.com/databendcloud/databend-go"
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

func (c *APIClient) ListWarehouses() ([]WarehouseStatusDTO, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses", c.CurrentOrgSlug)
	data := struct {
		Data []WarehouseStatusDTO `json:"data"`
	}{}
	err := c.DoRequest("GET", path, nil, nil, &data)
	if err != nil {
		return []WarehouseStatusDTO{}, fmt.Errorf("failed to view warehouse: %w", err)
	}
	return data.Data, err
}

func (c *APIClient) ViewWarehouse(warehouseName string) (*WarehouseStatusDTO, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s", c.CurrentOrgSlug, warehouseName)
	data := struct {
		Data WarehouseStatusDTO `json:"data"`
	}{}
	err := c.DoRequest("GET", path, nil, nil, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to view warehouse: %w", err)
	}
	return &data.Data, err
}

func (c *APIClient) ResumeWarehouse(warehouseName string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s/resume", c.CurrentOrgSlug, warehouseName)
	err := c.DoRequest("POST", path, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to resume warehouse: %w", err)
	}
	return nil
}

func (c *APIClient) SuspendWarehouse(warehouseName string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s/suspend", c.CurrentOrgSlug, warehouseName)
	err := c.DoRequest("POST", path, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to suspend warehouse: %w", err)
	}
	return nil
}

type CreateWarehouseRequestBody struct {
	ImageTag  string `json:"imageTag,omitempty"`
	Instances int64  `json:"instances,omitempty"`
	Name      string `json:"name,omitempty"`
	Size      string `json:"size,omitempty"`
}

func (c *APIClient) CreateWarehouse(warehouseName, size string) error {
	req := &CreateWarehouseRequestBody{
		Name: warehouseName,
		Size: size,
	}
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses", c.CurrentOrgSlug)
	err := c.DoRequest("POST", path, nil, req, nil)
	if err != nil {
		return fmt.Errorf("failed to create warehouse: %w", err)
	}
	return nil
}

func (c *APIClient) DeleteWarehouse(warehouseName string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s", c.CurrentOrgSlug, warehouseName)
	err := c.DoRequest("DELETE", path, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to delete warehouse: %w", err)
	}
	return nil
}

func (c *APIClient) CreateWarehouseAndWaitRunning(warehouseName, size string) error {
	err := c.CreateWarehouse(warehouseName, size)
	if err != nil {
		return err
	}
	err = retry.Do(
		func() (err error) {
			err = c.ResumeWarehouse(warehouseName)
			if err != nil {
				panic(err)
			}
			status, err := c.ViewWarehouse(warehouseName)
			if err != nil {
				panic(err)
			}
			if status.State != "Running" {
				return fmt.Errorf("state is %s", status.State)
			}
			return nil
		},
		retry.Delay(1*time.Second),
		retry.Attempts(10),
	)
	return err
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

func (c *APIClient) Query(warehouseName, query string) (*QueryResponse, error) {
	headers := make(http.Header)
	headers.Set("X-DATABENDCLOUD-WAREHOUSE", warehouseName)
	headers.Set("X-DATABENDCLOUD-ORG", string(c.CurrentOrgSlug))
	request := QueryRequest{
		SQL: query,
	}
	path := "/v1/query"
	var result QueryResponse
	err := c.DoRequest("POST", path, headers, request, &result)
	if err != nil {
		return nil, err
	}
	if result.Error != nil {
		return &result, fmt.Errorf("query %s in org %s has error: %v", warehouseName, c.CurrentOrgSlug, result.Error)
	}
	return &result, nil
}

func (c *APIClient) QuerySync(warehouseName string, sql string, respCh chan QueryResponse) error {
	var r0 *QueryResponse
	err := retry.Do(
		func() error {
			r, err := c.Query(warehouseName, sql)
			if err != nil {
				return fmt.Errorf("query failed: %w", err)
			}
			r0 = r
			return nil
		},
		// other err no need to retry
		retry.RetryIf(func(err error) bool {
			if err != nil && !(dc.IsProxyErr(err) || strings.Contains(err.Error(), dc.ProvisionWarehouseTimeout)) {
				return false
			}
			return true
		}),
		retry.Delay(2*time.Second),
		retry.Attempts(10),
	)
	if err != nil {
		return fmt.Errorf("query failed after 10 retries: %w", err)
	}
	if r0.Error != nil {
		return fmt.Errorf("query has error: %+v", r0.Error)
	}
	if err != nil {
		return err
	}
	respCh <- *r0
	nextUri := r0.NextURI
	for len(nextUri) != 0 {
		p, err := c.QueryPage(warehouseName, r0.Id, nextUri)
		if err != nil {
			return err
		}
		if p.Error != nil {
			return fmt.Errorf("query has error: %+v", p.Error)
		}
		nextUri = p.NextURI
		respCh <- *p
	}
	return nil
}

func (c *APIClient) QueryPage(warehouseName, queryId, path string) (*QueryResponse, error) {
	headers := make(http.Header)
	headers.Set("queryID", queryId)
	headers.Set("X-DATABENDCLOUD-WAREHOUSE", warehouseName)
	headers.Set("X-DATABENDCLOUD-ORG", string(c.CurrentOrgSlug))
	var result QueryResponse
	err := retry.Do(
		func() error {
			err := c.DoRequest("GET", path, headers, nil, &result)
			if err != nil {
				return fmt.Errorf("query failed: %w", err)
			}
			return nil
		},
		retry.Delay(2*time.Second),
		retry.Attempts(10),
	)
	if err != nil {
		return nil, err
	}
	return &result, nil
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

type WarehouseStatusDTO struct {
	Name           string `json:"id,omitempty"`
	ReadyInstances int64  `json:"readyInstances,omitempty"`
	Size           string `json:"size,omitempty"`
	State          string `json:"state,omitempty"`
	TotalInstances int64  `json:"totalInstances,omitempty"`
}

func (w WarehouseStatusDTO) String() string {
	return fmt.Sprintf("%s(%s):%s", w.Name, w.Size, w.State)
}

type AccountInfoDTO struct {
	ID              uint64    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	State           string    `json:"state"`
	AvatarURL       string    `json:"avatarURL"`
	DefaultOrgSlug  string    `json:"defaultOrgSlug"`
	PasswordEnabled bool      `json:"passwordEnabled"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type QueryError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Kind    string `json:"kind"`
}

type QueryResponse struct {
	Data     [][]interface{} `json:"data"`
	Error    *QueryError     `json:"error"`
	FinalURI string          `json:"final_uri"`
	Id       string          `json:"id"`
	NextURI  string          `json:"next_uri"`
	Schema   struct {
		Fields []struct {
			Name     string      `json:"name"`
			DataType interface{} `json:"data_type"`
		} `json:"fields"`
	} `json:"schema,omitempty"`
	State    string     `json:"state"`
	Stats    QueryStats `json:"stats"`
	StatsURI string     `json:"stats_uri"`
}

type QueryStats struct {
	RunningTimeMS float64       `json:"running_time_ms"`
	ScanProgress  QueryProgress `json:"scan_progress"`
}

type QueryProgress struct {
	Bytes uint64 `json:"bytes"`
	Rows  uint64 `json:"rows"`
}

type QueryRequest struct {
	SQL string `json:"sql"`
}

type OrgMembershipDTO struct {
	ID               OrgMemberID `json:"id"`
	AccountID        *AccountID  `json:"accountID"`
	AccountName      string      `json:"accountName"`
	AccountEmail     string      `json:"accountEmail"`
	OrgAvatarURL     string      `json:"orgAvatarURL"`
	AccountAvatarURL string      `json:"accountAvatarURL"`
	OrgSlug          string      `json:"orgSlug"`
	OrgName          string      `json:"orgName"`
	OrgState         string      `json:"orgState"`
	OrgTenantID      string      `json:"tenantID"`
	Region           string      `json:"region"`
	Provider         string      `json:"provider"`
	Gateway          string      `json:"gateway"`
	MemberKind       MemberKind  `json:"memberKind"`
	State            string      `json:"state"`
	UpdatedAt        time.Time   `json:"updatedAt"`
	CreatedAt        time.Time   `json:"createdAt"`
}

func (o OrgMembershipDTO) String() string {
	return fmt.Sprintf("(%s)[%s]%s@%s:%s", o.OrgState, o.OrgName, o.OrgSlug, o.Provider, o.Region)
}

type OrgMemberID uint64
type AccountID uint64
type MemberKind string
