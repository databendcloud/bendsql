package shell

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/xo/usql/drivers"
	"github.com/xo/usql/stmt"
)

// Lexer returns the syntax lexer for a driver.
func Lexer() chroma.Lexer {
	l := lexers.Get("sql")
	l.Config().EnsureNL = false
	return l
}

// RowsAffected returns the rows affected for the SQL result for a driver.
func RowsAffected(res sql.Result) (int64, error) {
	var count int64
	var err error
	count, err = res.RowsAffected()
	if err != nil && err.Error() == "no RowsAffected available after DDL statement" {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return count, nil
}

// ConvertBytes returns a func to handle converting bytes
func ConvertBytes() func([]byte, string) (string, error) {
	return func(buf []byte, _ string) (string, error) {
		return string(buf), nil
	}
}

// ConvertMap returns a func to handle converting a map[string]interface{}
func ConvertMap() func(map[string]interface{}) (string, error) {
	return func(v map[string]interface{}) (string, error) {
		buf, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(buf), nil
	}
}

// ConvertSlice returns a func to handle converting a []interface{}
func ConvertSlice() func([]interface{}) (string, error) {
	return func(v []interface{}) (string, error) {
		buf, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(buf), nil
	}
}

// ConvertDefault returns a func to handle converting a interface{}
func ConvertDefault() func(interface{}) (string, error) {
	return func(v interface{}) (string, error) {
		return fmt.Sprintf("%v", v), nil
	}
}

// Columns returns the column names for the SQL row result for a driver.
func Columns(rows *sql.Rows) ([]string, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	for i, c := range cols {
		if strings.TrimSpace(c) == "" {
			cols[i] = fmt.Sprintf("col%d", i)
		}
	}
	return cols, nil
}

// Version returns information about the database connection for a driver.
func Version(ctx context.Context, db *sql.DB) (string, error) {
	var ver string
	err := db.QueryRowContext(ctx, `SELECT version();`).Scan(&ver)
	if err != nil || ver == "" {
		ver = "<unknown>"
	}
	return ver, nil
}

// NewStmt wraps creating a new stmt.Stmt for a driver.
func NewStmt(f func() ([]rune, error), opts ...stmt.Option) *stmt.Stmt {
	return stmt.New(f, append(opts, stmtOpts()...)...)
}

// stmtOpts returns statement options for a driver.
func stmtOpts() []stmt.Option {
	return []stmt.Option{
		stmt.WithAllowDollar(true),
		stmt.WithAllowMultilineComments(true),
		stmt.WithAllowCComments(true),
		stmt.WithAllowHashComments(true),
	}
}

// Process processes the sql query for a driver.
func Process(prefix, sqlstr string) (string, string, bool, error) {
	typ, q := drivers.QueryExecType(prefix, sqlstr)
	return typ, sqlstr, q, nil
}
