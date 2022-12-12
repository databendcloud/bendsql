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

package shell

import (
	"context"
	"os"
	"os/user"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/xo/usql/drivers"
	"github.com/xo/usql/env"
	"github.com/xo/usql/handler"
	"github.com/xo/usql/rline"

	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

func NewCmdShell(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Enter interactive sql shell",
		Long:  "Enter interactive sql shell",
		Annotations: map[string]string{
			"IsCore": "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.GetConfig()
			if err != nil {
				return err
			}
			dsn, err := cfg.GetDSN()
			if err != nil {
				return errors.Wrap(err, "failed to get dsn")
			}

			// register databend driver
			drivers.Register("databend", drivers.Driver{
				UseColumnTypes: true,
			})

			// load current user
			cur, err := user.Current()
			if err != nil {
				return errors.Wrap(err, "failed to get current user")
			}
			wd, err := os.Getwd()
			if err != nil {
				return errors.Wrap(err, "failed to get current working directory")
			}

			// create input/output
			l, err := rline.New(false, "", env.HistoryFile(cur))
			if err != nil {
				return errors.Wrap(err, "failed to create readline")
			}
			defer l.Close()
			// create handler
			h := handler.New(l, cur, wd, true)
			// open dsn
			if err = h.Open(context.Background(), dsn); err != nil {
				return errors.Wrap(err, "failed to open dsn")
			}
			return h.Run()
		},
	}

	return cmd
}
