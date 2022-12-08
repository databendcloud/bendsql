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
	stageListCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/stage/stage_ls"
	stageUploadCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud/stage/stage_upload"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

func NewStageCmd(f *cmdutil.Factory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stage <command>",
		Short: "Operate stage",
		Annotations: map[string]string{
			"IsCore": "true",
		},
	}

	cmd.AddCommand(stageUploadCmd.NewCmdStageUpload(f))
	cmd.AddCommand(stageListCmd.NewCmdStageList(f))

	return cmd
}
