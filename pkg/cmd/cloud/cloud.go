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

package cloud

import (
	"github.com/spf13/cobra"

	configureCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/configure"
	loginCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/login"
	warehouseCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/warehouse"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

// NewCloudCmd represents the cloud command
func NewCloudCmd(f *cmdutil.Factory) *cobra.Command {
	cloudCmd := &cobra.Command{
		Use:   "cloud cmd",
		Short: "Operate Databend Cloud",
		Long: `Operate Databend Cloud. For example:
            bendsql cloud login
            bendsql cloud warehouse ls
            bendsql cloud warehouse status YOUR_WAREHOUSE
            bendsql cloud warehouse suspend YOUR_WAREHOUSE`,
		Annotations: map[string]string{
			"IsCore": "true",
		},
	}
	cloudCmd.AddCommand(configureCmd.NewCmdConfigure(f))
	cloudCmd.AddCommand(loginCmd.NewCmdLogin(f))
	cloudCmd.AddCommand(warehouseCmd.NewWarehouseCmd(f))

	return cloudCmd
}
