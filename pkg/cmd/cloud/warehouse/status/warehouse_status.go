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

	"github.com/pkg/errors"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

func NewCmdWarehouseStatus(f *cmdutil.Factory) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "status warehouseName",
		Short: "show warehouse status",
		Long:  "show warehouse status",
		Args:  cobra.MaximumNArgs(1),
		Example: heredoc.Doc(`
			# show warehouse status
			$ bendsql warehouse status WAREHOUSENAME
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			apiClient, err := f.ApiClient()
			if err != nil {
				return errors.Wrap(err, "new api client failed")
			}
			var warehouse string
			switch len(args) {
			case 0:
				warehouse = apiClient.CurrentWarehouse()
			case 1:
				warehouse = args[0]
			default:
				return errors.Wrap(err, "wrong params, example: bendsql warehouse status WAREHOUSENAME")
			}

			warehouseStatus, err := apiClient.ViewWarehouse(warehouse)
			if err != nil {
				return errors.Wrap(err, "show warehouse status failed")
			}
			fmt.Printf("warehouse %s status is %s, size is %s, readyInstance is %d, totalInstance is %d\n",
				warehouseStatus.Name, warehouseStatus.State,
				warehouseStatus.Size, warehouseStatus.ReadyInstances,
				warehouseStatus.TotalInstances)
			return nil
		},
	}

	return cmd
}
