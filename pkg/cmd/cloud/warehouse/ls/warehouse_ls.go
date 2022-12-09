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

func NewCmdWarehouseList(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "show warehouse list",
		Long:  "show warehouse list",
		Example: heredoc.Doc(`
			# show warehouse list
			$ bendsql warehouse ls
		`),
		Run: func(cmd *cobra.Command, args []string) {
			err := showWarehouseList(f)
			if err != nil {
				fmt.Printf("show warehouse list failed, err: %v", err)
			}
		},
	}

	return cmd
}

func showWarehouseList(f *cmdutil.Factory) error {
	apiClient, err := api.NewClient()
	if err != nil {
		return err
	}
	warehouseList, err := apiClient.ListWarehouses()
	if err != nil {
		return err
	}
	for _, warehouse := range warehouseList {
		fmt.Println(warehouse.Description(), warehouse.Name)
	}

	return nil
}
