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
	"os/user"

	"github.com/spf13/cobra"
	"github.com/xo/usql/rline"

	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/shell"
)

func NewCmdShell(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Enter interactive sql shell",
		Long:  "Enter interactive sql shell",
		Run: func(cmd *cobra.Command, args []string) {
			cur, err := user.Current()
			if err != nil {
				panic(err)
			}
			apiClient, err := f.ApiClient()
			if err != nil {
				panic(err)
			}

			// create input/output
			l, err := rline.New(false, "", "")
			if err != nil {
				panic(err)
			}
			defer l.Close()

			// create handler
			h := shell.NewHandler(l, cur, apiClient)

			// open dsn
			if err = h.Open(context.Background()); err != nil {
				panic(err)
			}
			err = h.Run()
			if err != nil {
				panic(err)
			}

		},
	}

	return cmd
}
