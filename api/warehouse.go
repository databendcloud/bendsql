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
	"time"

	"github.com/avast/retry-go"
)

func (c *APIClient) ListWarehouses() ([]WarehouseStatusDTO, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses", c.cfg.Org)
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
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s", c.cfg.Org, warehouseName)
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
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s/resume", c.cfg.Org, warehouseName)
	err := c.DoRequest("POST", path, nil, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to resume warehouse: %w", err)
	}
	return nil
}

func (c *APIClient) SuspendWarehouse(warehouseName string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s/suspend", c.cfg.Org, warehouseName)
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
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses", c.cfg.Org)
	err := c.DoRequest("POST", path, nil, req, nil)
	if err != nil {
		return fmt.Errorf("failed to create warehouse: %w", err)
	}
	return nil
}

func (c *APIClient) DeleteWarehouse(warehouseName string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/tenant/warehouses/%s", c.cfg.Org, warehouseName)
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
