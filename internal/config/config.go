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
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"

	"gopkg.in/ini.v1"
)

var (
	once sync.Once
)

const (
	KeyUserEmail    string = "user_email"
	KeyAccessToken  string = "access_token"
	KeyRefreshToken string = "refresh_token"
	KeyExpiresAt    string = "expires_at"
	KeyWarehouse    string = "warehouse"
	KeyOrg          string = "org"
	KeyTenant       string = "tenant"
	KeyEndpoint     string = "endpoint"
	KeyGateway      string = "gateway"
)

const (
	bendsqlConfigDir  = "BENDSQL_CONFIG_DIR"
	bendsqlCinfigFile = "bendsql.ini"
)

type Config struct {
	Org       string `ini:"org"`
	Tenant    string `ini:"tenant"`
	Warehouse string `ini:"warehouse"`
	Gateway   string `ini:"gateway"`
	Endpoint  string `init:"endpoint"`

	Auth *Token `ini:"auth"`
}

type Token struct {
	AccessToken  string    `ini:"access_token"`
	RefreshToken string    `ini:"refresh_token"`
	ExpiresAt    time.Time `ini:"expires_at"`
}

type Configer interface {
	Get(string) (string, error)
	Set(string, string) error
	GetAuth() (*Token, error)
	SetAuth(*Token) error
}

func GetConfig() (Configer, error) {
	c, err := Read()
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Write() error {
	if Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		err := os.RemoveAll(ConfigDir())
		if err != nil {
			return err
		}
	}
	if !Exists(ConfigDir()) {
		err := os.MkdirAll(ConfigDir(), os.ModePerm)
		if err != nil {
			return err
		}
	}
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		_, err := os.Create(filepath.Join(ConfigDir(), bendsqlCinfigFile))
		if err != nil {
			return err
		}
	}
	cg := ini.Empty()
	defaultSection := cg.Section("")
	defaultSection.NewKey(KeyWarehouse, c.Warehouse)
	defaultSection.NewKey(KeyOrg, c.Org)
	defaultSection.NewKey(KeyTenant, c.Tenant)
	defaultSection.NewKey(KeyEndpoint, c.Endpoint)
	defaultSection.NewKey(KeyGateway, c.Gateway)

	authSection := cg.Section("auth")
	authSection.NewKey(KeyAccessToken, c.Auth.AccessToken)
	authSection.NewKey(KeyRefreshToken, c.Auth.RefreshToken)
	authSection.NewKey(KeyExpiresAt, c.Auth.ExpiresAt.Format(time.RFC3339))

	return cg.SaveTo(filepath.Join(ConfigDir(), bendsqlCinfigFile))
}

// Get a string value from a ConfigFile.
func (c *Config) Get(key string) (string, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return "", nil
	}
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return "", errors.Wrap(err, "fail to read config file")
	}
	return cfg.Section("").Key(key).String(), nil
}

func (c *Config) Set(key, value string) error {
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return errors.Wrap(err, "fail to read config file")
	}
	cfg.Section("").Key(key).SetValue(value)
	err = cfg.SaveTo(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return errors.Wrap(err, "fail to save config file")
	}
	return nil
}

func (c *Config) GetAuth() (*Token, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return nil, nil
	}
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return nil, errors.Wrap(err, "fail to read config file")
	}
	authSection := cfg.Section("auth")
	accessToken := authSection.Key(KeyAccessToken).String()
	refreshToken := authSection.Key(KeyRefreshToken).String()
	expiresAt, err := authSection.Key(KeyExpiresAt).Time()
	if err != nil {
		return nil, errors.Wrap(err, "fail to parse token expires")
	}
	auth := &Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}
	return auth, nil
}

func (c *Config) SetAuth(auth *Token) error {
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return errors.Wrap(err, "fail to read config file")
	}
	authSection := cfg.Section("auth")
	authSection.Key(KeyAccessToken).SetValue(auth.AccessToken)
	authSection.Key(KeyRefreshToken).SetValue(auth.RefreshToken)
	authSection.Key(KeyExpiresAt).SetValue(auth.ExpiresAt.Format(time.RFC3339))
	err = cfg.SaveTo(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		return errors.Wrap(err, "fail to save config file")
	}
	return nil
}

func getField(key string) (string, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return "", nil
	}
	cfg, err := GetConfig()
	if err != nil {
		return "", errors.Wrap(err, "read config failed")
	}
	value, err := cfg.Get(key)
	if err != nil {
		return "", errors.Wrap(err, "get field failed")
	}
	return value, nil
}

func GetWarehouse() string {
	warehouse, _ := getField(KeyWarehouse)
	return warehouse
}

func GetEndpoint() string {
	endpoint, _ := getField(KeyEndpoint)
	return endpoint
}

func GetOrg() string {
	org, _ := getField(KeyOrg)
	return org
}

func GetTenant() string {
	tenant, _ := getField(KeyTenant)
	return tenant
}

func GetGateway() string {
	gateway, _ := getField(KeyGateway)
	return gateway
}

func setField(key, value string) error {
	cfg, err := GetConfig()
	if err != nil {
		return errors.Wrap(err, "read config failed")
	}
	err = cfg.Set(key, value)
	if err != nil {
		return errors.Wrapf(err, "set field %s failed", key)
	}
	return nil
}

func SetUsingWarehouse(warehouse string) error {
	return setField(KeyWarehouse, warehouse)
}

func GetToken() (*Token, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return nil, nil
	}
	cfg, err := GetConfig()
	if err != nil {
		return nil, errors.Wrap(err, "read config failed")
	}
	return cfg.GetAuth()
}

func SetToken(token *Token) error {
	cfg, err := GetConfig()
	if err != nil {
		return errors.Wrap(err, "read config failed")
	}
	return cfg.SetAuth(token)
}

func ConfigDir() string {
	var path string
	if a := os.Getenv(bendsqlConfigDir); a != "" {
		path = a
	} else {
		d, _ := os.UserHomeDir()
		path = filepath.Join(d, ".config", "bendsql")
	}
	return path
}

// Read bendsql configuration files from the local file system and
// return a Config.
func Read() (*Config, error) {
	var err error
	var iniCfg *ini.File
	cfg := &Config{}
	once.Do(func() {
		iniCfg, err = ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
		err = iniCfg.MapTo(cfg)
	})
	return cfg, err
}

func Exists(path string) bool {
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
