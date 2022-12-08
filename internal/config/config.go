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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

const (
	configDirEnv = "BENDSQL_CONFIG_DIR"
)

var (
	configFile = ""
)

func init() {
	var configDir string
	if a := os.Getenv(configDirEnv); a != "" {
		configDir = a
	} else {
		d, _ := os.UserHomeDir()
		configDir = filepath.Join(d, ".config", "bendsql")
	}
	configFile = filepath.Join(configDir, "config.json")
	if !exists(configFile) {
		fmt.Printf("config file %s not found, creating a new one\n", configFile)
		if !exists(filepath.Dir(configFile)) {
			err := os.MkdirAll(filepath.Dir(configFile), 0755)
			if err != nil {
				panic(err)
			}
		}
		f, err := os.Create(configFile)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		f.Write([]byte("{}"))
	}
}

type Config struct {
	Org       string `json:"org"`
	Tenant    string `json:"tenant"`
	Warehouse string `json:"warehouse"`
	Gateway   string `json:"gateway"`
	Endpoint  string `json:"endpoint"`

	Token *Token `json:"token,omitempty"`
}

type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func GetConfig() (*Config, error) {
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "read config file")
	}
	var cfg Config
	err = json.Unmarshal(content, &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal config file")
	}
	return &cfg, nil
}

func WriteConfig(cfg *Config) error {
	content, err := json.Marshal(cfg)
	if err != nil {
		return errors.Wrap(err, "marshal config")
	}
	err = os.WriteFile(configFile, content, 0644)
	if err != nil {
		return errors.Wrap(err, "write config file")
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		if os.IsNotExist(err) {
			return false
		}
		return false
	}
	return true
}
