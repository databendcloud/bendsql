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
	completionCmd "github.com/databendcloud/bendsql/pkg/cmd/completion"
	configureCmd "github.com/databendcloud/bendsql/pkg/cmd/configure"
	loginCmd "github.com/databendcloud/bendsql/pkg/cmd/login"
	queryCmd "github.com/databendcloud/bendsql/pkg/cmd/query"
	shellCmd "github.com/databendcloud/bendsql/pkg/cmd/shell"
	stageCmd "github.com/databendcloud/bendsql/pkg/cmd/stage"
	versionCmd "github.com/databendcloud/bendsql/pkg/cmd/version"
	warehouseCmd "github.com/databendcloud/bendsql/pkg/cmd/warehouse"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands

func NewCmdRoot(f *cmdutil.Factory, version, buildDate string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bendsql <command> <subcommand> [flags]",
		Short: "Dababend Cloud CLI",
		Long:  `Work seamlessly with Databend Cloud from the command line.`,

		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ bendsql login
			$ bendsql configure
			$ bendsql warehouse status
			$ bendsql warehouse create
			$ bendsql stage ls
		`),
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
	cmd.AddCommand(loginCmd.NewCmdLogin(f))
	cmd.AddCommand(configureCmd.NewCmdConfigure(f))
	cmd.AddCommand(warehouseCmd.NewWarehouseCmd(f))
	cmd.AddCommand(stageCmd.NewCmdStage(f))
	cmd.AddCommand(queryCmd.NewCmdQuerySQL(f))
	cmd.AddCommand(shellCmd.NewCmdShell(f))
	return cmd
}
