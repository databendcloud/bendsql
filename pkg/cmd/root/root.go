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

package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	cloudCmd "github.com/databendcloud/bendsql/pkg/cmd/cloud"
	completionCmd "github.com/databendcloud/bendsql/pkg/cmd/completion"
	queryCmd "github.com/databendcloud/bendsql/pkg/cmd/query"
	shellCmd "github.com/databendcloud/bendsql/pkg/cmd/shell"
	versionCmd "github.com/databendcloud/bendsql/pkg/cmd/version"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
)

// rootCmd represents the base command when called without any subcommands

func NewCmdRoot(f *cmdutil.Factory, version, buildDate string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bendsql <command> <subcommand> [flags]",
		Short: "Dababend CLI",
		Long:  `Work seamlessly with Databend & Databend Cloud from the command line.`,

		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ bendsql cloud login
			$ bendsql cloud warehouse ls
			$ bendsql shell
			$ bendsql query`),
		Annotations: map[string]string{
			"versionInfo": versionCmd.Format(version, buildDate),
		},
	}

	cmd.SetErr(f.IOStreams.ErrOut) // just let it default to os.Stderr instead

	cmd.Flags().Bool("version", false, "Show bendsql version")
	cmd.PersistentFlags().Bool("help", false, "Show help for command")
	cmd.SetHelpFunc(func(c *cobra.Command, args []string) {
		rootHelpFunc(f, c, args)
	})
	cmd.SetUsageFunc(func(c *cobra.Command) error {
		return rootUsageFunc(f.IOStreams.ErrOut, c)
	})
	cmd.SetFlagErrorFunc(rootFlagErrorFunc)

	// Child commands
	cmd.AddCommand(versionCmd.NewCmdVersion(f, version, buildDate))
	cmd.AddCommand(completionCmd.NewCmdCompletion(f.IOStreams))
	cmd.AddCommand(cloudCmd.NewCloudCmd(f))
	cmd.AddCommand(queryCmd.NewCmdQuerySQL(f))
	cmd.AddCommand(shellCmd.NewCmdShell(f))
	return cmd
}
