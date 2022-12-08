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
	"time"

	"github.com/avast/retry-go"
	"github.com/pkg/errors"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

func NewCmdWarehouseResume(f *cmdutil.Factory) *cobra.Command {
	var wait bool
	cmd := &cobra.Command{
		Use:   "resume warehouseName --wait",
		Short: "Resume a warehouse",
		Long:  "Resume a warehouse",
		Args:  cobra.MaximumNArgs(1),
		Example: heredoc.Doc(`
			# resume a warehouse and return until the warehouse running
			$ bendsql warehouse resume WAREHOUSENAME --wait

			# resume a warehouse and return
			$ bendsql warehouse resume WAREHOUSENAME
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			apiClient, err := f.ApiClient()
			if err != nil {
				return errors.Wrap(err, "get api client failed")
			}
			var warehouse string
			switch len(args) {
			case 0:
				warehouse = apiClient.CurrentWarehouse()
			case 1:
				warehouse = args[0]
			default:
				return errors.New("wrong params, example: bendsql warehouse resume WAREHOUSENAME")
			}
			err = resumeWarehouse(apiClient, warehouse, wait)
			if err != nil {
				return errors.Wrapf(err, "resume warehouse %s failed", warehouse)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&wait, "wait", false, "Wait until resume warehouse success")
	return cmd
}

func resumeWarehouse(apiClient *api.APIClient, warehouseName string, wait bool) error {
	err := apiClient.ResumeWarehouse(warehouseName)
	if err != nil {
		return errors.Wrap(err, "resume warehouse failed")
	}

	if wait {
		err = retry.Do(
			func() (err error) {
				status, err := apiClient.ViewWarehouse(warehouseName)
				if err != nil {
					panic(err)
				}
				if status.State != "Running" {
					return fmt.Errorf("resume warehouse %s timeout, state is %s", warehouseName, status.State)
				}
				fmt.Printf("resume warehouse %s success", warehouseName)
				return nil
			},
			retry.Delay(1*time.Second),
			retry.Attempts(20),
		)
		if err != nil {
			return errors.Wrap(err, "wait for resume warehouse failed")
		}
	}
	fmt.Printf("resume warehouse %s done, please use `bendsql warehouse status WAREHOUSENAME` to check", warehouseName)
	return nil
}
