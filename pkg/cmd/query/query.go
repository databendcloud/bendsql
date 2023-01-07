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

package query

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/MakeNowJust/heredoc"
	_ "github.com/databendcloud/databend-go"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
)

type querySQLOptions struct {
	IO       *iostreams.IOStreams
	QuerySQL string
	Verbose  bool
}

func NewCmdQuerySQL(f *cmdutil.Factory) *cobra.Command {
	opts := &querySQLOptions{
		IO: f.IOStreams,
	}
	var sqlStdin bool

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Exec query SQL using warehouse",
		Long:  "Exec query SQL using warehouse",
		Example: heredoc.Doc(`
			# exec SQL using warehouse
			# use sql
			$ bendsql query "YOURSQL" [--verbose]

			# use stdin
			$ echo "select * from YOURTABLE limit 10" | bendsql query
		`),
		Annotations: map[string]string{
			"IsCore": "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.QuerySQL = args[0]
			}

			if len(opts.QuerySQL) == 0 {
				sqlStdin = true
			}
			if sqlStdin {
				defer opts.IO.In.Close()
				sql, err := io.ReadAll(opts.IO.In)
				if err != nil {
					fmt.Printf("failed to read sql from standard input: %v", err)
					os.Exit(1)
				}
				opts.QuerySQL = strings.TrimSpace(string(sql))
			}

			cfg, err := config.GetConfig()
			if err != nil {
				return errors.Wrap(err, "failed to get config")
			}

			dsn, err := cfg.GetDSN()
			if err != nil {
				return errors.Wrap(err, "failed to get dsn")
			}

			err = execQueryByDriver(opts, dsn)
			if err != nil {
				fmt.Printf("exec query failed, err: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&opts.Verbose, "verbose", false, "display progress info across paginated results")

	return cmd
}

func execQueryByDriver(opts *querySQLOptions, dsn string) error {
	db, err := sql.Open("databend", dsn)
	if err != nil {
		return errors.Wrap(err, "failed to open databend driver")
	}
	defer db.Close()

	rows, err := db.Query(opts.QuerySQL)
	if err != nil {
		return errors.Wrap(err, "failed to query")
	}
	_, err = scanValues(rows)
	if err != nil {
		return errors.Wrap(err, "failed to scan values")
	}
	return nil
}

func scanValues(rows *sql.Rows) ([][]interface{}, error) {
	var err error
	var result [][]interface{}
	ct, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	types := make([]reflect.Type, len(ct))
	for i, v := range ct {
		types[i] = v.ScanType()
	}
	ptrs := make([]interface{}, len(types))
	for rows.Next() {
		if err = rows.Err(); err != nil {
			return nil, err
		}
		for i, t := range types {
			ptrs[i] = reflect.New(t).Interface()
		}
		err = rows.Scan(ptrs...)
		if err != nil {
			return nil, err
		}
		values := make([]interface{}, len(types))
		for i, p := range ptrs {
			values[i] = reflect.ValueOf(p).Elem().Interface()
		}
		result = append(result, values)
	}

	beautyPrintRows(result, ct)
	return result, nil
}

func beautyPrintRows(rows [][]interface{}, columnTypes []*sql.ColumnType) {
	columnNames := table.Row{}
	for i := range columnTypes {
		columnNames = append(columnNames, columnTypes[i].Name())
	}
	tableRows := make([]table.Row, 0, len(rows))
	for i := range rows {
		tableRows = append(tableRows, rows[i])
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(columnNames)
	t.AppendRows(tableRows)
	t.AppendSeparator()
	t.Style().Color.Header = text.Colors{text.FgGreen}
	t.Render()
}
