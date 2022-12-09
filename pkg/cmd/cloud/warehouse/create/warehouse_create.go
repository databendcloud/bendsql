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
	"github.com/spf13/cobra"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

func NewCmdWarehouseCreate(f *cmdutil.Factory) *cobra.Command {

	var size string
	cmd := &cobra.Command{
		Use:   "create warehouseName",
		Short: "Create a warehouse",
		Long:  "Create a warehouse",
		Example: heredoc.Doc(`
			# create a warehouse, the size has Small, Medium, Large, default is Small
			$ bendsql warehouse create WAREHOUSENAME --size Small
		`),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 1 {
				fmt.Printf("Wrong params, example: bendsql warehouse create WAREHOUSENAME \n")
				return
			}
			if len(args) == 0 {
				fmt.Printf("No warehouseName, example: bendsql warehouse create WAREHOUSENAME \n")
				return
			}
			err := createWarehouse(f, args[0], size)
			if err != nil {
				fmt.Printf("create warehouse %s failed, err: %v", args[0], err)
				return
			}
			fmt.Printf("warehouse %s created, size is %s", args[0], size)
		},
	}
	cmd.Flags().StringVar(&size, "size", "Small", "Warehouse size")

	return cmd
}

func createWarehouse(f *cmdutil.Factory, warehouseName, size string) error {
	fmt.Printf("warehouse %s is creating, please wait...\n", warehouseName)
	apiClient, err := api.NewClient()
	if err != nil {
		return err
	}
	err = apiClient.CreateWarehouse(warehouseName, size)
	if err != nil {
		return err
	}
	return nil
}
