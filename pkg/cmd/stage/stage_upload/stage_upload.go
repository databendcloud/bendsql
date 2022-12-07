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
	"fmt"
	"path/filepath"

	"github.com/databendcloud/bendsql/internal/config"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/iostreams"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type uploadOptions struct {
	IO        *iostreams.IOStreams
	ApiClient func() (*api.APIClient, error)
	Warehouse string
	StageName string
	InsertSQL string
	FileName  string
}

func NewCmdStageUpload(f *cmdutil.Factory) *cobra.Command {
	opts := &uploadOptions{
		IO:        f.IOStreams,
		ApiClient: f.ApiClient,
	}
	var warehouse string

	cmd := &cobra.Command{
		Use:   "upload FILE STAGE",
		Short: "Upload file to stage using warehouse",
		Long:  "Upload file to stage using warehouse",
		Example: heredoc.Doc(`
			# upload file to stage using warehouse with flag
			$ bendsql stage upload FILE STAGE --warehouse [WAREHOUSENAME]
		`),
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) <= 0 || len(args) > 2 {
				cmd.Help()
				return
			}
			filePath := args[0]
			stageName := args[1]

			cfg, err := config.GetConfig()
			if err != nil {
				panic(err)
			}

			if warehouse == "" {
				// TODO: check the warehouse whether in warehouse list
				warehouse, err = cfg.Get(config.KeyWarehouse)
				if warehouse == "" || err != nil {
					fmt.Printf("--warehouse is required")
					return
				}
			}

			opts.Warehouse = warehouse
			opts.StageName = stageName
			opts.FileName = filePath
			err = uploadToStage(opts)
			if err != nil {
				fmt.Printf("upload file to stage failed, err: %v", err)
				return
			}
			fmt.Printf("upload file %s to stage %s successfully", filePath, stageName)
		},
	}

	cmd.Flags().StringVar(&warehouse, "warehouse", "", "warehouse")
	return cmd
}

func uploadToStage(opts *uploadOptions) error {
	fmt.Printf("uploading %s to stage %s... \n", opts.FileName, opts.StageName)
	apiClient, err := opts.ApiClient()
	if err != nil {
		return err
	}
	presignUploadSQL := fmt.Sprintf("PRESIGN UPLOAD @%s/%s", opts.StageName, filepath.Base(opts.FileName))
	resp, err := apiClient.Query(opts.Warehouse, presignUploadSQL)
	if err != nil {
		return err
	}
	if len(resp.Data) < 1 || len(resp.Data[0]) < 2 {
		return fmt.Errorf("generate presign url failed")
	}
	headers, ok := resp.Data[0][1].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no host for presign url")
	}
	return apiClient.UploadToStageByPresignURL(fmt.Sprintf("%v", resp.Data[0][2]), opts.FileName, headers, true)
}
