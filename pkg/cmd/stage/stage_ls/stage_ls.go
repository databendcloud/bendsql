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

package stage

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/iostreams"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type lsOptions struct {
	IO        *iostreams.IOStreams
	ApiClient func() (*api.APIClient, error)
	StageName string
	Warehouse string
	InsertSQL string
	FileName  string
}

func NewCmdStageList(f *cmdutil.Factory) *cobra.Command {
	opts := &lsOptions{
		IO:        f.IOStreams,
		ApiClient: f.ApiClient,
	}
	var stage string

	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List stage or files in stage",
		Long:  "List stage or files in stage",
		Args:  cobra.MaximumNArgs(1),
		Example: heredoc.Doc(`
			# list all stages in your account
			$ bendsql stage ls
			# list the files in the stage
			$ bendsql stage ls @StageName
			# list the file info in @stage
			$ bendsql stage ls @StageName/FileName
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			apiClient, err := opts.ApiClient()
			if err != nil {
				return errors.Wrap(err, "get api client failed")
			}
			warehouse := apiClient.CurrentWarehouse()
			if warehouse == "" {
				return errors.New("no warehouse selected, use bendsql warehouse use to select a warehouse")
			}

			opts.Warehouse = warehouse
			opts.StageName = stage

			switch len(args) {
			case 0:
				opts.InsertSQL = "SHOW STAGES;"
				err = listStage(apiClient, opts)
				if err != nil {
					return errors.Wrap(err, "list stage failed")
				}
			case 1:
				// has stage name, show the files in stage
				stage = args[0]
				opts.InsertSQL = fmt.Sprintf("list %s", stage)
				err := listStage(apiClient, opts)
				if err != nil {
					return errors.Wrapf(err, "list files in stage %s failed", stage)
				}
			}
			return nil
		},
	}

	return cmd
}

func listStage(apiClient *api.APIClient, opts *lsOptions) error {
	var stagesStr string
	queryResp, err := apiClient.Query(opts.Warehouse, opts.InsertSQL)
	if err != nil {
		return err
	}
	for i := range queryResp.Data {
		b, err := json.Marshal(queryResp.Data[i])
		if err != nil {
			return err
		}
		stagesStr += string(b) + "\n"
	}

	fmt.Println(stagesStr)
	return nil
}
