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

package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/databendcloud/bendsql/utils"

	"github.com/spf13/cobra"

	surveyCore "github.com/AlecAivazis/survey/v2/core"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/databendcloud/bendsql/internal/build"
	"github.com/databendcloud/bendsql/pkg/cmd/root"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
	"github.com/mgutz/ansi"
)

type exitCode int

const (
	exitOK     exitCode = 0
	exitError  exitCode = 1
	exitCancel exitCode = 2
	exitAuth   exitCode = 4
)

func main() {
	code := mainRun()
	os.Exit(int(code))
}

func mainRun() exitCode {
	buildDate := build.Date
	buildVersion := build.Version

	cmdFactory := cmdutil.NewFactory()
	stderr := cmdFactory.IOStreams.ErrOut
	hasDebug := utils.IsDebugEnabled()

	if !cmdFactory.IOStreams.ColorEnabled() {
		surveyCore.DisableColor = true
	} else {
		// override survey's poor choice of color
		surveyCore.TemplateFuncsWithColor["color"] = func(style string) string {
			switch style {
			case "white":
				if cmdFactory.IOStreams.ColorSupport256() {
					return fmt.Sprintf("\x1b[%d;5;%dm", 38, 242)
				}
				return ansi.ColorCode("default")
			default:
				return ansi.ColorCode(style)
			}
		}
	}

	authError := errors.New("authError")

	rootCmd := root.NewCmdRoot(cmdFactory, buildVersion, buildDate)
	if cmd, err := rootCmd.ExecuteC(); err != nil {
		var pagerPipeError *iostreams.ErrClosedPagerPipe
		var noResultsError cmdutil.NoResultsError
		if err == cmdutil.SilentError {
			return exitError
		} else if cmdutil.IsUserCancellation(err) {
			if errors.Is(err, terminal.InterruptErr) {
				// ensure the next shell prompt will start on its own line
				fmt.Fprint(stderr, "\n")
			}
			return exitCancel
		} else if errors.Is(err, authError) {
			return exitAuth
		} else if errors.As(err, &pagerPipeError) {
			// ignore the error raised when piping to a closed pager
			return exitOK
		} else if errors.As(err, &noResultsError) {
			if cmdFactory.IOStreams.IsStdoutTTY() {
				fmt.Fprintln(stderr, noResultsError.Error())
			}
			// no results is not a command failure
			return exitOK
		}
		printError(stderr, err, cmd, hasDebug)

		return exitError
	}
	return exitOK
}

func printError(out io.Writer, err error, cmd *cobra.Command, debug bool) {
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		fmt.Fprintf(out, "error connecting to %s\n", dnsError.Name)
		if debug {
			fmt.Fprintln(out, dnsError)
		}
		fmt.Fprintln(out, "please check your network")
		return
	}
	fmt.Fprintln(out, err)

	var flagError *cmdutil.FlagError
	if errors.As(err, &flagError) || strings.HasPrefix(err.Error(), "unknown command ") {
		if !strings.HasSuffix(err.Error(), "\n") {
			fmt.Fprintln(out)
		}
		fmt.Fprintln(out, cmd.UsageString())
	}
}
