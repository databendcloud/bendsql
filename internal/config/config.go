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
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"gopkg.in/ini.v1"
)

var (
	once sync.Once
)

const (
	KeyUserEmail    string = "user_email"
	KeyAccessToken  string = "access_token"
	KeyRefreshToken string = "refresh_token"
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
	UserEmail    string `ini:"user_email"`
	AccessToken  string `ini:"access_token"`
	RefreshToken string `ini:"refresh_token"`
	Warehouse    string `ini:"warehouse"`
	Tenant       string `ini:"tenant"`
	Org          string `ini:"org"`
	Gateway      string `ini:"gateway"`
	Endpoint     string `init:"endpoint"`
}

type Configer interface {
	AuthToken() (string, string, error)
	Get(string) (string, error)
	Set(string, string) error
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
	defaultSection.NewKey(KeyAccessToken, c.AccessToken)
	defaultSection.NewKey(KeyRefreshToken, c.RefreshToken)
	defaultSection.NewKey(KeyWarehouse, c.Warehouse)
	defaultSection.NewKey(KeyOrg, c.Org)
	defaultSection.NewKey(KeyTenant, c.Tenant)
	defaultSection.NewKey(KeyUserEmail, c.UserEmail)
	defaultSection.NewKey(KeyEndpoint, c.Endpoint)
	defaultSection.NewKey(KeyGateway, c.Gateway)
	return cg.SaveTo(filepath.Join(ConfigDir(), bendsqlCinfigFile))
}

func (c *Config) AuthToken() (string, string, error) {
	accessToken, err := c.Get(KeyAccessToken)
	if err != nil {
		return "", "", err
	}
	refreshToken, err := c.Get(KeyRefreshToken)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// Get a string value from a ConfigFile.
func (c *Config) Get(key string) (string, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return "", nil
	}
	log := logrus.WithField("bendsql", "get")
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		log.Errorf("Fail to read file: %v", err)
		return "", err
	}
	return cfg.Section("").Key(key).String(), nil
}

func (c *Config) Set(key, value string) error {
	log := logrus.WithField("bendsql", "set")
	cfg, err := ini.Load(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		log.Errorf("Fail to read file: %v", err)
		return err
	}
	cfg.Section("").Key(key).SetValue(value)
	err = cfg.SaveTo(filepath.Join(ConfigDir(), bendsqlCinfigFile))
	if err != nil {
		log.Errorf("Fail to save file: %v", err)
		return err
	}
	return nil
}

func RenewTokens(accessToken, refreshToken string) error {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return os.ErrNotExist
	}
	cfg, err := GetConfig()
	if err != nil {
		return errors.Wrap(err, "config failed")
	}
	err = cfg.Set(KeyAccessToken, accessToken)
	if err != nil {
		return errors.Wrap(err, "set access token failed")
	}
	err = cfg.Set(KeyRefreshToken, refreshToken)
	if err != nil {
		return errors.Wrap(err, "set refresh token failed")
	}
	return nil
}

func SetUsingWarehouse(warehouse string) error {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return os.ErrNotExist
	}
	cfg, err := GetConfig()
	if err != nil {
		return fmt.Errorf("config failed: %w", err)
	}
	err = cfg.Set(KeyWarehouse, warehouse)
	if err != nil {
		return fmt.Errorf("set warehouse failed %w", err)
	}
	return nil
}

func GetAuthToken() (string, string, error) {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return "", "", os.ErrNotExist
	}
	cfg, err := GetConfig()
	if err != nil {
		return "", "", errors.Wrap(err, "read config failed")
	}
	return cfg.AuthToken()
}

func getField(key string) string {
	if !Exists(filepath.Join(ConfigDir(), bendsqlCinfigFile)) {
		return ""
	}
	cfg, err := GetConfig()
	if err != nil {
		logrus.Errorf("read config failed %v", err)
		return ""
	}
	value, err := cfg.Get(key)
	if err != nil {
		logrus.Errorf("get %s failed %v", key, err)
		return ""
	}
	return value
}

func GetWarehouse() string {
	return getField(KeyWarehouse)
}

func GetEndpoint() string {
	return getField(KeyEndpoint)
}

func GetUserEmail() string {
	return getField(KeyUserEmail)
}

func GetOrg() string {
	return getField(KeyOrg)
}

func GetTenant() string {
	return getField(KeyTenant)
}

func GetGateway() string {
	return getField(KeyGateway)
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
