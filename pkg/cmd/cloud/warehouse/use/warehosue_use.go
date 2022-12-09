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

package warehouse

import (
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

func NewCmdWarehouseUse(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use",
		Short: "select working warehouse",
		Long:  "select working warehouse",
		Args:  cobra.ExactArgs(1),
		Example: heredoc.Doc(`
			# "select working warehouse",
			$ bendsql warehouse use WORKINGWAREHOUSE
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			apiClient, err := api.NewClient()
			if err != nil {
				return errors.Wrap(err, "get api client failed")
			}
			warehouse := args[0]
			err = apiClient.SetCurrentWarehouse(warehouse)
			if err != nil {
				return errors.Wrapf(err, "set working warehouse %s failed", warehouse)
			}

			fmt.Printf("Now using warehouse %s", warehouse)
			return nil
		},
	}

	return cmd
}
