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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func NewMockConfig(cfg *Config) Configer {
	return cfg
}

func TestConfig(t *testing.T) {
	args := []Config{{
		UserEmail:    "databend@datafuse.com",
		AccessToken:  "xxx",
		RefreshToken: "yyy",
		Warehouse:    "test",
		Org:          "databend",
	},
		{
			UserEmail:    "databend1@datafuse.com",
			AccessToken:  "xxx",
			RefreshToken: "yyy",
			Warehouse:    "test",
			Org:          "databend1",
		},
		{
			UserEmail:    "databend2@datafuse.com",
			AccessToken:  "xxx",
			RefreshToken: "yyy",
			Warehouse:    "test",
			Org:          "databend2",
		},
	}

	for i := range args {
		c := NewMockConfig(&args[i])
		err := args[i].Write()
		assert.NoError(t, err)
		warehouse, err := c.Get(KeyWarehouse)
		assert.NoError(t, err)
		assert.Equal(t, args[i].Warehouse, warehouse)
		email, err := c.Get(KeyUserEmail)
		assert.NoError(t, err)
		assert.Equal(t, args[i].UserEmail, email)
		accessToken, err := c.Get(KeyAccessToken)
		assert.NoError(t, err)
		assert.Equal(t, args[i].AccessToken, accessToken)
		refreshToken, err := c.Get(KeyRefreshToken)
		assert.NoError(t, err)
		assert.Equal(t, args[i].RefreshToken, refreshToken)
		org, err := c.Get(KeyOrg)
		assert.NoError(t, err)
		assert.Equal(t, args[i].Org, org)
	}
	for i := range args {
		c := NewMockConfig(&args[i])
		err := c.Set(KeyWarehouse, "ddd")
		assert.NoError(t, err)
		warehouse, _ := c.Get(KeyWarehouse)
		assert.Equal(t, "ddd", warehouse)

		err = c.Set(KeyOrg, "org1")
		assert.NoError(t, err)
		org, _ := c.Get(KeyOrg)
		assert.Equal(t, "org1", org)

	}

	defer clean()
}

func clean() {
	os.RemoveAll(ConfigDir())
}
