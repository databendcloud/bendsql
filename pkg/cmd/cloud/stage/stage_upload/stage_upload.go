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

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
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
		Args:  cobra.ExactArgs(2),
		Example: heredoc.Doc(`
			# upload file to stage using warehouse with flag
			$ bendsql stage upload FILE STAGE --warehouse [WAREHOUSENAME]
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			filePath := args[0]
			stageName := args[1]

			apiClient, err := opts.ApiClient()
			if err != nil {
				return err
			}

			if warehouse == "" {
				warehouse = apiClient.CurrentWarehouse()
			}
			if warehouse == "" {
				return errors.New("no warehouse selected")
			}

			opts.Warehouse = warehouse
			opts.StageName = stageName
			opts.FileName = filePath
			err = uploadToStage(apiClient, opts)
			if err != nil {
				return errors.Wrap(err, "upload file to stage failed")
			}
			fmt.Printf("upload file %s to stage %s successfully\n", filePath, stageName)
			return nil
		},
	}

	cmd.Flags().StringVar(&warehouse, "warehouse", "", "warehouse")
	return cmd
}

func uploadToStage(apiClient *api.APIClient, opts *uploadOptions) error {
	fmt.Printf("uploading %s to stage %s... \n", opts.FileName, opts.StageName)
	presignUploadSQL := fmt.Sprintf("PRESIGN UPLOAD @%s/%s", opts.StageName, filepath.Base(opts.FileName))
	resp, err := apiClient.Query(opts.Warehouse, presignUploadSQL)
	if err != nil {
		return err
	}
	if len(resp.Data) < 1 || len(resp.Data[0]) < 2 {
		return errors.Errorf("generate presign url failed")
	}
	headers, ok := resp.Data[0][1].(map[string]interface{})
	if !ok {
		return errors.Errorf("no host for presign url")
	}
	return apiClient.UploadToStageByPresignURL(fmt.Sprintf("%v", resp.Data[0][2]), opts.FileName, headers, true)
}
