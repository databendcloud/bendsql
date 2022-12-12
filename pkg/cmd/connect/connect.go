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

package connect

import (
	"database/sql"
	"fmt"

	_ "github.com/databendcloud/databend-go"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

type connectOptions struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSL      bool
}

func NewCmdConnect(f *cmdutil.Factory) *cobra.Command {
	opts := &connectOptions{}
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect to Databend Instance",
		Long:  "Connect to Databend Instance",
		Annotations: map[string]string{
			"IsCore": "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.GetConfig()
			if err != nil {
				return err
			}
			cfg.Target = config.TARGET_COMMUNITY
			cfg.Community = &config.CommunityConfig{
				Host:     opts.Host,
				Port:     opts.Port,
				User:     opts.User,
				Password: opts.Password,
				Database: opts.Database,
				SSL:      opts.SSL,
			}

			dsn, err := cfg.Community.GetDSN()
			if err != nil {
				return err
			}
			version, err := getVersion(dsn)
			if err != nil {
				return errors.Wrap(err, "failed to get databend version")
			}

			fmt.Printf("Connected to Databend on Host: %s\nVersion: %s\n", opts.Host, version)

			err = config.WriteConfig(cfg)
			if err != nil {
				return errors.Wrap(err, "failed to write config")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.Host, "host", "H", "localhost", "")
	cmd.Flags().IntVarP(&opts.Port, "port", "P", 8000, "")
	cmd.Flags().StringVarP(&opts.User, "user", "u", "root", "")
	cmd.Flags().StringVarP(&opts.Password, "password", "p", "", "")
	cmd.Flags().StringVarP(&opts.Database, "database", "d", "default", "")
	cmd.Flags().BoolVarP(&opts.SSL, "ssl", "", false, "")

	return cmd
}

func getVersion(dsn string) (version string, err error) {
	db, err := sql.Open("databend", dsn)
	if err != nil {
		return "", errors.Wrap(err, "failed to open databend driver")
	}
	defer db.Close()

	err = db.QueryRow("SELECT version()").Scan(&version)
	return
}
