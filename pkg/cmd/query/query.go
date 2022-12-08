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
	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	_ "github.com/databendcloud/databend-go"
)

type querySQLOptions struct {
	IO        *iostreams.IOStreams
	ApiClient func() (*api.APIClient, error)
	Warehouse string
	QuerySQL  string
	Verbose   bool
}

func NewCmdQuerySQL(f *cmdutil.Factory) *cobra.Command {
	opts := &querySQLOptions{
		IO:        f.IOStreams,
		ApiClient: f.ApiClient,
	}
	var sqlStdin bool

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Exec query SQL using warehouse",
		Long:  "Exec query SQL using warehouse",
		Example: heredoc.Doc(`
			# exec SQL using warehouse
			# use sql
			$ bendsql query "YOURSQL" --warehouse [WAREHOUSENAME] [--verbose]

			# use stdin
			$ echo "select * from YOURTABLE limit 10" | bendsql query
		`),
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

			apiClient, err := opts.ApiClient()
			if err != nil {
				return errors.Wrap(err, "failed to get api client")
			}

			if opts.Warehouse == "" {
				opts.Warehouse = apiClient.CurrentWarehouse()
			}
			if opts.Warehouse == "" {
				return errors.Wrap(err, "warehouse not selected")
			}

			dsn, err := apiClient.GetCloudDSN()
			if err != nil {
				return errors.Wrap(err, "failed to get cloud dsn")
			}

			err = execQueryByDriver(opts, dsn)
			if err != nil {
				fmt.Printf("exec query failed, err: %v\n", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Warehouse, "warehouse", "", "warehouse")
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

	var schemaStr string
	for i := range ct {
		schemaStr += fmt.Sprintf("| %v(%s) ", ct[i].Name(), types[i])
	}
	fmt.Println(schemaStr + " |")
	for i := range result {
		var a string
		for j := range result[i] {
			a += fmt.Sprintf("| %v ", result[i][j])
		}
		a += "| \n"
		fmt.Println(a)
	}
	return result, nil
}
