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
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

const (
	configFileEnv = "BENDSQL_CONFIG"
)

var (
	configFile = ""
)

func init() {
	if a := os.Getenv(configFileEnv); a != "" {
		configFile = a
	} else {
		d, err := os.UserHomeDir()
		if err != nil {
			panic(err)
		}
		configFile = filepath.Join(d, ".config", "bendsql", "config.toml")
	}
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
	}
}

type Config struct {
	Org       string `toml:"org"`
	Tenant    string `toml:"tenant"`
	Warehouse string `toml:"warehouse"`
	Gateway   string `toml:"gateway"`
	Endpoint  string `toml:"endpoint"`

	Token *Token `toml:"token,omitempty"`
}

type Token struct {
	AccessToken  string    `toml:"access_token"`
	RefreshToken string    `toml:"refresh_token"`
	ExpiresAt    time.Time `toml:"expires_at"`
}

func GetConfig() (*Config, error) {
	content, err := os.ReadFile(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "read config file")
	}
	var cfg Config
	_, err = toml.Decode(string(content), &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshal config file")
	}
	return &cfg, nil
}

func WriteConfig(cfg *Config) error {
	file, err := os.OpenFile(configFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.Wrap(err, "open config file")
	}
	err = toml.NewEncoder(file).Encode(cfg)
	if err != nil {
		return errors.Wrap(err, "encode config file")
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
