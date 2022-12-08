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

	"github.com/databendcloud/bendsql/internal/config"

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
		Example: heredoc.Doc(`
			# list all stages in your account
			$ bendsql stage ls
			# list the files in the stage
			$ bendsql stage ls @StageName
			# list the file info in @stage
			$ bendsql stage ls @StageName/FileName
		`),
		Run: func(cmd *cobra.Command, args []string) {
			opts.StageName = stage
			opts.Warehouse = config.GetWarehouse()
			// has stage name, show the files in stage
			if len(args) == 1 {
				stage = args[0]
				opts.InsertSQL = fmt.Sprintf("list %s", stage)
				err := listStage(opts)
				if err != nil {
					fmt.Printf("list files in stage %s failed, err: %v", stage, err)
				}
				return
			}

			opts.InsertSQL = "SHOW STAGES;"
			err := listStage(opts)
			if err != nil {
				fmt.Printf("list stage failed, err: %v", err)
				return
			}
		},
	}

	return cmd
}

func listStage(opts *lsOptions) error {
	var stagesStr string
	apiClient, err := opts.ApiClient()
	if err != nil {
		return err
	}
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
