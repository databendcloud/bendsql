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
	warehouseCreateCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/create"
	warehouseDeleteCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/delete"
	warehouseListCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/ls"
	warehouseResumeCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/resume"
	warehouseStatusCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/status"
	warehouseSuspendCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/suspend"
	warehouseUseCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse/use"
	"github.com/databendcloud/bendsql/pkg/cmdutil"

	"github.com/spf13/cobra"
)

// NewWarehouseCmd represents the warehouse command
func NewWarehouseCmd(f *cmdutil.Factory) *cobra.Command {
	warehouseCmd := &cobra.Command{
		Use:   "warehouse cmd",
		Short: "Operate warehouse",
		Long: `Operate warehouse. For example:
            bendsql warehouse ls
            bendsql warehouse status YOUR_WAREHOUSE
            bendsql warehouse suspend YOUR_WAREHOUSE
`,
		Annotations: map[string]string{
			"IsCore": "true",
		},
	}
	warehouseCmd.AddCommand(warehouseStatusCmd.NewCmdWarehouseStatus(f))
	warehouseCmd.AddCommand(warehouseListCmd.NewCmdWarehouseList(f))
	warehouseCmd.AddCommand(warehouseResumeCmd.NewCmdWarehouseResume(f))
	warehouseCmd.AddCommand(warehouseSuspendCmd.NewCmdWarehouseSuspend(f))
	warehouseCmd.AddCommand(warehouseCreateCmd.NewCmdWarehouseCreate(f))
	warehouseCmd.AddCommand(warehouseDeleteCmd.NewCmdWarehouseDelete(f))
	warehouseCmd.AddCommand(warehouseUseCmd.NewCmdWarehouseUse(f))
	return warehouseCmd
}
