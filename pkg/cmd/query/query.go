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
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
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
	var warehouse, querySQL string
	var sqlStdin bool
	var verbose bool

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
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 1 {
				querySQL = args[0]
			}
			opts.Warehouse = warehouse
			opts.QuerySQL = querySQL
			opts.Verbose = verbose

			cfg, err := config.GetConfig()
			if err != nil {
				panic(err)
			}
			if len(querySQL) == 0 {
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

			if warehouse == "" {
				// TODO: check the warehouse whether in warehouse list
				warehouse, err = cfg.Get(config.KeyWarehouse)
				if warehouse == "" || err != nil {
					fmt.Printf("get default warehouse failed, please your default warehouse in $HOME/.config/bendsql/bendsql.ini")
					os.Exit(1)
				}
				opts.Warehouse = warehouse
			}
			err = execQueryByDriver(opts)
			if err != nil {
				fmt.Printf("exec query failed, err: %v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&warehouse, "warehouse", "", "warehouse")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "display progress info across paginated results")

	return cmd
}

func newDatabendCloudDSN(opts *querySQLOptions) (string, error) {
	apiClient, err := opts.ApiClient()
	if err != nil {
		return "", err
	}
	return apiClient.GetCloudDSN()
}

func execQueryByDriver(opts *querySQLOptions) error {
	dsn, err := newDatabendCloudDSN(opts)
	if err != nil {
		return err
	}
	db, err := sql.Open("databend", dsn)
	if err != nil {
		log.Fatalf("failed to connect. %v, err: %v", dsn, err)
	}
	defer db.Close()

	rows, err := db.Query(opts.QuerySQL)
	if err != nil {
		return err
	}
	_, err = scanValues(rows)
	if err != nil {
		return err
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
