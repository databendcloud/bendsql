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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/avast/retry-go"
	dc "github.com/databendcloud/databend-go"
)

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
