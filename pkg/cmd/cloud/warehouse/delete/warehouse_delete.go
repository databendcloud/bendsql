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
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

func NewCmdWarehouseDelete(f *cmdutil.Factory) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "delete warehouseName",
		Short: "Delete a warehouse",
		Long:  "Delete a warehouse",
		Example: heredoc.Doc(`
			# delete a warehouse
			$ bendsql warehouse delete WAREHOUSENAME
		`),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 1 {
				fmt.Printf("Wrong params, example: bendsql warehouse delete WAREHOUSENAME \n")
				return
			}
			if len(args) == 0 {
				fmt.Printf("No warehouseName, example: bendsql warehouse delete WAREHOUSENAME \n")
				return
			}
			err := deleteWarehouse(f, args[0])
			if err != nil {
				fmt.Printf("delete warehouse %s failed, err: %v", args[0], err)
				return
			}
			fmt.Printf("warehouse %s deleted", args[0])
		},
	}
	return cmd
}

func deleteWarehouse(f *cmdutil.Factory, warehouseName string) error {
	apiClient, err := f.ApiClient()
	if err != nil {
		return err
	}
	err = apiClient.DeleteWarehouse(warehouseName)
	if err != nil {
		return err
	}
	return nil
}
