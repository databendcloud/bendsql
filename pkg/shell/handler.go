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

package shell

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/pkg/errors"
	"github.com/xo/tblfmt"
	"github.com/xo/usql/drivers"
	"github.com/xo/usql/env"
	"github.com/xo/usql/metacmd"
	"github.com/xo/usql/rline"
	"github.com/xo/usql/stmt"
	ustyles "github.com/xo/usql/styles"
	"github.com/xo/usql/text"

	"github.com/databendcloud/bendsql/api"
	_ "github.com/databendcloud/databend-go"
)

type Handler struct {
	l    rline.IO
	user *user.User
	// timing of every command executed
	timing bool
	// singleLineMode is single line mode
	singleLineMode bool
	// query statement buffer
	buf *stmt.Stmt
	// last statement
	last       string
	lastPrefix string
	lastRaw    string
	// batch
	batch    bool
	batchEnd string
	// out file or pipe
	out io.WriteCloser

	db *sql.DB

	apiClient *api.APIClient
}

func NewHandler(l rline.IO, u *user.User, apiClient *api.APIClient) *Handler {
	f, iactive := l.Next, l.Interactive()
	if iactive {
		f = func() ([]rune, error) {
			// next line
			r, err := l.Next()
			if err != nil {
				return nil, err
			}
			// save history
			_ = l.Save(string(r))
			return r, nil
		}
	}
	h := &Handler{
		l:         l,
		user:      u,
		apiClient: apiClient,
		buf:       stmt.New(f),
	}
	if iactive {
		l.SetOutput(h.outputHighlighter)
	}
	return h
}

// outputHighlighter returns s as a highlighted string, based on the current
// buffer and syntax highlighting settings.
func (h *Handler) outputHighlighter(s string) string {
	// bail when string is empty (ie, contains no printable, non-space
	// characters) or if syntax highlighting is not enabled
	if empty(s) || env.All()["SYNTAX_HL"] != "true" {
		return s
	}
	// count end lines
	var endl string
	for strings.HasSuffix(s, lineterm) {
		s = strings.TrimSuffix(s, lineterm)
		endl += lineterm
	}
	// leading whitespace
	var leading string
	// capture current query statement buffer
	orig := h.buf.RawString()
	full := orig
	if full != "" {
		full += "\n"
	} else {
		// get leading whitespace
		if i := strings.IndexFunc(s, func(r rune) bool {
			return !stmt.IsSpaceOrControl(r)
		}); i != -1 {
			leading = s[:i]
		}
	}
	full += s
	// setup statement parser
	st := NewStmt(func() func() ([]rune, error) {
		y := strings.Split(orig, "\n")
		if y[0] == "" {
			y[0] = s
		} else {
			y = append(y, s)
		}
		return func() ([]rune, error) {
			if len(y) > 0 {
				z := y[0]
				y = y[1:]
				return []rune(z), nil
			}
			return nil, io.EOF
		}
	}())
	// accumulate all "active" statements in buffer, breaking either at
	// EOF or when a \ cmd has been encountered
	var err error
	var cmd, final string
loop:
	for {
		cmd, _, err = st.Next(env.Unquote(h.user, false, env.All()))
		switch {
		case err != nil && err != io.EOF:
			return s + endl
		case err == io.EOF:
			break loop
		}
		if st.Ready() || cmd != "" {
			final += st.RawString()
			st.Reset(nil)
			// grab remaining whitespace to add to final
			l := len(final)
			// find first non empty character
			if i := strings.IndexFunc(full[l:], func(r rune) bool {
				return !stmt.IsSpaceOrControl(r)
			}); i != -1 {
				final += full[l : l+i]
			}
		}
	}
	if !st.Ready() && cmd == "" {
		final += st.RawString()
	}
	final = leading + final
	// determine whatever is remaining after "active"
	var remaining string
	if fnl := len(final); fnl < len(full) {
		remaining = full[fnl:]
	}
	// this happens when a read line is empty and/or has only
	// whitespace and a \ cmd
	if s == remaining {
		return s + endl
	}
	// highlight entire final accumulated buffer
	b := new(bytes.Buffer)
	if err := h.Highlight(b, final); err != nil {
		return s + endl
	}
	colored := b.String()
	// return only last line plus whatever remaining string (ie, after
	// a \ cmd) and the end line count
	ss := strings.Split(colored, "\n")
	return lastcolor(colored) + ss[len(ss)-1] + remaining + endl
}

// helpQuitExitRE is a regexp to use to match help, quit, or exit messages.
var helpQuitExitRE = regexp.MustCompile(fmt.Sprintf(`(?im)^(%s|%s|%s)\s*$`, text.HelpPrefix, text.QuitPrefix, text.ExitPrefix))

// Run executes queries and commands.
func (h *Handler) Run() error {
	stdout, stderr, iactive := h.l.Stdout(), h.l.Stderr(), h.l.Interactive()
	// display welcome info
	if iactive {
		fmt.Fprintln(h.l.Stdout(), text.WelcomeDesc)
		fmt.Fprintln(h.l.Stdout())
	}
	var lastErr error
	for {
		fmt.Println("start loop: ", h.buf.RawString())
		var execute bool
		// set prompt
		if iactive {
			h.l.Prompt(h.Prompt(env.Get("PROMPT1")))
		}
		// read next statement/command
		cmd, paramstr, err := h.buf.Next(env.Unquote(h.user, false, env.All()))
		switch {
		case h.singleLineMode && err == nil:
			execute = h.buf.Len != 0
		case err == rline.ErrInterrupt:
			h.buf.Reset(nil)
			continue
		case err != nil:
			if err == io.EOF {
				return lastErr
			}
			return err
		}
		fmt.Println("cmd: ", cmd)
		var opt metacmd.Option
		if cmd != "" {
			cmd = strings.TrimPrefix(cmd, `\`)
			params := stmt.DecodeParams(paramstr)
			// decode
			// r, err := metacmd.Decode(cmd, params)
			// if err != nil {
			// 	lastErr = errors.Wrap(err, cmd)
			// 	switch {
			// 	case err == text.ErrUnknownCommand:
			// 		fmt.Fprintln(stderr, fmt.Sprintf(text.InvalidCommand, cmd))
			// 	case err == text.ErrMissingRequiredArgument:
			// 		fmt.Fprintln(stderr, fmt.Sprintf(text.MissingRequiredArg, cmd))
			// 	default:
			// 		fmt.Fprintln(stderr, "error:", err)
			// 	}
			// 	continue
			// }
			// run
			// opt, err = r.Run(h)
			// if err != nil && err != rline.ErrInterrupt {
			// 	lastErr = errors.Wrap(err, cmd)
			// 	fmt.Fprintln(stderr, "error:", err)
			// 	continue
			// }

			// print unused command parameters
			for {
				ok, arg, err := params.Get(func(s string, isvar bool) (bool, string, error) {
					return true, s, nil
				})
				if err != nil {
					fmt.Fprintln(stderr, "error:", err)
				}
				if !ok {
					break
				}
				fmt.Fprintln(stdout, fmt.Sprintf(text.ExtraArgumentIgnored, cmd, arg))
			}
		}
		// help, exit, quit intercept
		if iactive && len(h.buf.Buf) >= 4 {
			i, first := stmt.RunesLastIndex(h.buf.Buf, '\n'), false
			if i == -1 {
				i, first = 0, true
			}
			if s := strings.ToLower(helpQuitExitRE.FindString(string(h.buf.Buf[i:]))); s != "" {
				if s := strings.ToLower(helpQuitExitRE.FindString(string(h.buf.Buf[i:]))); s != "" {
					switch s {
					case "help":
						s = text.HelpDescShort
						if first {
							s = text.HelpDesc
							h.buf.Reset(nil)
						}
					case "quit", "exit":
						s = text.QuitDesc
						if first {
							return nil
						}
					}
					fmt.Fprintln(stdout, s)
				}
			}
			// quit
			if opt.Quit {
				if h.out != nil {
					h.out.Close()
				}
				return nil
			}
			// execute buf
			if execute || h.buf.Ready() || opt.Exec != metacmd.ExecNone {
				if h.buf.Len != 0 {
					h.last, h.lastPrefix, h.lastRaw = h.buf.String(), h.buf.Prefix, h.buf.RawString()
					h.buf.Reset(nil)
				}
				// log.Printf(">> PROCESS EXECUTE: (%s) `%s`", h.lastPrefix, h.last)
				if !h.batch && h.last != "" && h.last != ";" {
					// execute
					out := stdout
					if h.out != nil {
						out = h.out
					}
					ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
					if err = h.Execute(ctx, out, opt, h.lastPrefix, h.last); err != nil {
						lastErr = errors.Wrap(err, h.last)
						if env.All()["ON_ERROR_STOP"] == "on" {
							if iactive {
								fmt.Fprintln(stderr, "error:", err)
								h.buf.Reset([]rune{}) // empty the buffer so no other statements are run
								continue
							} else {
								stop()
								return err
							}
						} else {
							fmt.Fprintln(stderr, "error:", err)
						}
					}
					stop()
				}
			}
		}
	}
}

// Execute executes a query against the connected database.
func (h *Handler) Execute(ctx context.Context, w io.Writer, opt metacmd.Option, prefix, sqlstr string) error {
	if h.db == nil {
		return text.ErrNotConnected
	}
	// determine type and pre process string
	prefix, sqlstr, qtyp, err := Process(prefix, sqlstr)
	if err != nil {
		return err
	}

	f := h.execSingle
	switch opt.Exec {
	case metacmd.ExecExec:
		f = h.execExec
	case metacmd.ExecSet:
		f = h.execSet
	case metacmd.ExecWatch:
		f = h.execWatch
	}
	err = f(ctx, w, opt, prefix, sqlstr, qtyp)
	if err != nil {
		return err
	}
	return nil
}

// Reset resets the handler's query statement buffer.
func (h *Handler) Reset(r []rune) {
	h.buf.Reset(r)
	h.last, h.lastPrefix, h.lastRaw, h.batch, h.batchEnd = "", "", "", false, ""
}

func (h *Handler) Prompt(prompt string) string {
	var buf []byte
	buf = append(buf, []byte("(databend)=> ")...)
	return string(buf)
}

// IO returns the io for the handler.
func (h *Handler) IO() rline.IO {
	return h.l
}

// User returns the user for the handler.
func (h *Handler) User() *user.User {
	return h.user
}

// // URL returns the current database URL.
// func (h *Handler) URL() *dburl.URL {
// 	return h.u
// }

// DB returns the current database connection.
func (h *Handler) DB() drivers.DB {
	return h.db
}

// Last returns the last executed statement.
func (h *Handler) Last() string {
	return h.last
}

// LastRaw returns the last raw (non-interpolated) executed statement.
func (h *Handler) LastRaw() string {
	return h.lastRaw
}

// Buf returns the current query statement buffer.
func (h *Handler) Buf() *stmt.Stmt {
	return h.buf
}

// ChangePassword changes the password for a user.
func (h *Handler) ChangePassword(string) (string, error) {
	// TODO: implement
	return "", nil
}

// Include includes a file.
func (h *Handler) Include(string, bool) error {
	// TODO: implement
	return nil
}

// Begin begins a transaction.
func (h *Handler) Begin(*sql.TxOptions) error {
	// TODO: implement
	return nil
}

// Commit commits the current transaction.
func (h *Handler) Commit() error {
	// TODO: implement
	return nil
}

// Rollback aborts the current transaction.
func (h *Handler) Rollback() error {
	// TODO: implement
	return nil
}

// GetTiming gets the timing toggle.
func (h *Handler) GetTiming() bool {
	return h.timing
}

// SetTiming sets the timing toggle.
func (h *Handler) SetTiming(timing bool) {
	h.timing = timing
}

// // MetadataWriter loads the metadata writer for the
// func (h *Handler) MetadataWriter(ctx context.Context) (metadata.Writer, error) {
// 	if h.db == nil {
// 		return nil, text.ErrNotConnected
// 	}
// 	return drivers.NewMetadataWriter(ctx, h.u, h.db, h.l.Stdout(), readerOpts()...)
// }

// Highlight highlights using the current environment settings.
func (h *Handler) Highlight(w io.Writer, buf string) error {
	vars := env.All()
	// create lexer, formatter, styler
	l := chroma.Coalesce(Lexer())
	f := formatters.Get(vars["SYNTAX_HL_FORMAT"])
	s := styles.Get(vars["SYNTAX_HL_STYLE"])
	// override background
	if vars["SYNTAX_HL_OVERRIDE_BG"] != "false" {
		s = ustyles.Get(vars["SYNTAX_HL_STYLE"])
	}
	// tokenize stream
	it, err := l.Tokenise(nil, buf)
	if err != nil {
		return err
	}
	// write formatted output
	return f.Format(w, s, it)
}

func (h *Handler) Open(ctx context.Context, params ...string) error {
	dsn, err := h.apiClient.GetCloudDSN()
	if err != nil {
		return err
	}

	h.db, err = sql.Open("databend", dsn)
	if err != nil {
		defer h.Close()
		return errors.Wrapf(err, "open %s", dsn)
	}

	err = h.db.PingContext(ctx)
	if err != nil {
		defer h.Close()
		return errors.Wrapf(err, "ping %s", dsn)
	}

	return h.Version(ctx)
}

// Close closes the database connection if it is open.
func (h *Handler) Close() error {
	if h.db != nil {
		err := h.db.Close()
		h.db = nil
		return err
	}
	return nil
}

// ReadVar reads a variable from the interactive prompt, saving it to
// environment variables.
func (h *Handler) ReadVar(typ, prompt string) (string, error) {
	var masked bool
	// check type
	switch typ {
	case "password":
		masked = true
	case "string", "int", "uint", "float", "bool":
	default:
		return "", text.ErrInvalidType
	}
	var v string
	var err error
	if masked {
		if prompt == "" {
			prompt = text.EnterPassword
		}
		v, err = h.l.Password(prompt)
	} else {
		h.l.Prompt(prompt)
		var r []rune
		r, err = h.l.Next()
		v = string(r)
	}
	switch typ {
	case "int":
		_, err = strconv.ParseInt(v, 10, 64)
	case "uint":
		_, err = strconv.ParseUint(v, 10, 64)
	case "float":
		_, err = strconv.ParseFloat(v, 64)
	case "bool":
		var b bool
		b, err = strconv.ParseBool(v)
		if err == nil {
			v = fmt.Sprintf("%v", b)
		}
	}
	if err != nil {
		errstr := err.Error()
		if i := strings.LastIndex(errstr, ":"); i != -1 {
			errstr = strings.TrimSpace(errstr[i+1:])
		}
		return "", fmt.Errorf(text.InvalidValue, typ, v, errstr)
	}
	return v, nil
}

// Version prints the database version information after a successful connection.
func (h *Handler) Version(ctx context.Context) error {
	if h.db == nil {
		return text.ErrNotConnected
	}
	ver, err := Version(ctx, h.db)
	if err != nil {
		ver = fmt.Sprintf("<unknown, error: %v>", err)
	}
	if ver != "" {
		h.Print(text.ConnInfo, ver)
	}
	return nil
}

// Print formats according to a format specifier and writes to handler's standard output.
func (h *Handler) Print(format string, a ...interface{}) {
	if env.Get("QUIET") == "on" {
		return
	}
	fmt.Fprintln(h.l.Stdout(), fmt.Sprintf(format, a...))
}

// execWatch repeatedly executes a query against the database.
func (h *Handler) execWatch(ctx context.Context, w io.Writer, opt metacmd.Option, prefix, sqlstr string, qtyp bool) error {
	for {
		// this is the actual output that psql has: "Mon Jan 2006 3:04:05 PM MST"
		// fmt.Fprintf(w, "%s (every %fs)\n\n", time.Now().Format("Mon Jan 2006 3:04:05 PM MST"), float64(opt.Watch)/float64(time.Second))
		fmt.Fprintf(w, "%s (every %v)\n", time.Now().Format(time.RFC1123), opt.Watch)
		fmt.Fprintln(w)
		if err := h.execSingle(ctx, w, opt, prefix, sqlstr, qtyp); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		case <-time.After(opt.Watch):
		}
	}
}

// execSingle executes a single query against the database based on its query type.
func (h *Handler) execSingle(ctx context.Context, w io.Writer, opt metacmd.Option, prefix, sqlstr string, qtyp bool) error {
	// exec or query
	f := h.exec
	if qtyp {
		f = h.query
	}
	// exec
	return f(ctx, w, opt, prefix, sqlstr)
}

// execSet executes a SQL query, setting all returned columns as variables.
func (h *Handler) execSet(ctx context.Context, w io.Writer, opt metacmd.Option, prefix, sqlstr string, _ bool) error {
	// query
	rows, err := h.db.QueryContext(ctx, sqlstr)
	if err != nil {
		return err
	}
	// get cols
	cols, err := Columns(rows)
	if err != nil {
		return err
	}
	// process row(s)
	var i int
	var row []string
	clen, tfmt := len(cols), env.GoTime()
	for rows.Next() {
		if i == 0 {
			row, err = h.scan(rows, clen, tfmt)
			if err != nil {
				return err
			}
		}
		i++
	}
	if i > 1 {
		return text.ErrTooManyRows
	}
	// set vars
	for i, c := range cols {
		n := opt.Params["prefix"] + c
		if err = env.ValidIdentifier(n); err != nil {
			return fmt.Errorf(text.CouldNotSetVariable, n)
		}
		_ = env.Set(n, row[i])
	}
	return nil
}

// execExec executes a query and re-executes all columns of all rows as if they
// were their own queries.
func (h *Handler) execExec(ctx context.Context, w io.Writer, _ metacmd.Option, prefix, sqlstr string, _ bool) error {
	// query
	rows, err := h.db.QueryContext(ctx, sqlstr)
	if err != nil {
		return err
	}
	// execRows
	if err := h.execRows(ctx, w, rows); err != nil {
		return err
	}
	// check for additional result sets ...
	for rows.NextResultSet() {
		if err := h.execRows(ctx, w, rows); err != nil {
			return err
		}
	}
	return nil
}

// query executes a query against the database.
func (h *Handler) query(ctx context.Context, w io.Writer, opt metacmd.Option, typ, sqlstr string) error {
	start := time.Now()
	// run query
	rows, err := h.db.QueryContext(ctx, sqlstr)
	if err != nil {
		return err
	}
	defer rows.Close()
	params := env.Pall()
	params["time"] = env.GoTime()
	for k, v := range opt.Params {
		params[k] = v
	}
	var pipe io.WriteCloser
	var cmd *exec.Cmd
	if pipeName := params["pipe"]; pipeName != "" || h.out != nil {
		if params["expanded"] == "auto" && params["columns"] == "" {
			// don't rely on terminal size when piping output to a file or cmd
			params["expanded"] = "off"
		}
		if pipeName != "" {
			if pipeName[0] == '|' {
				pipe, cmd, err = env.Pipe(pipeName[1:])
			} else {
				pipe, err = os.OpenFile(pipeName, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o644)
			}
			if err != nil {
				return err
			}
			w = pipe
		}
	} else if opt.Exec != metacmd.ExecWatch {
		params["pager_cmd"] = env.All()["PAGER"]
	}
	useColumnTypes := false
	// wrap query with crosstab
	resultSet := tblfmt.ResultSet(rows)
	if opt.Exec == metacmd.ExecCrosstab {
		var err error
		resultSet, err = tblfmt.NewCrosstabView(rows, tblfmt.WithParams(opt.Crosstab...), tblfmt.WithUseColumnTypes(useColumnTypes))
		if err != nil {
			return err
		}
		useColumnTypes = false
	}
	if useColumnTypes {
		params["use_column_types"] = "true"
	}
	// encode and handle error conditions
	switch err := tblfmt.EncodeAll(w, resultSet, params); {
	case err != nil && cmd != nil && errors.Is(err, syscall.EPIPE):
		// broken pipe means pager quit before consuming all data, which might be expected
		return nil
	case err != nil:
		return err
	case params["format"] == "aligned":
		fmt.Fprintln(w)
	}
	if h.timing {
		d := time.Since(start)
		format := text.TimingDesc
		v := []interface{}{float64(d.Microseconds()) / 1000}
		if d > 1*time.Second {
			format += " (%v)"
			v = append(v, d.Round(1*time.Millisecond))
		}
		h.Print(format, v...)
	}
	if pipe != nil {
		pipe.Close()
		if cmd != nil {
			cmd.Wait()
		}
	}
	return err
}

// execRows executes all the columns in the row.
func (h *Handler) execRows(ctx context.Context, w io.Writer, rows *sql.Rows) error {
	// get columns
	cols, err := Columns(rows)
	if err != nil {
		return err
	}
	// process rows
	res := metacmd.Option{Exec: metacmd.ExecOnly}
	clen, tfmt := len(cols), env.GoTime()
	for rows.Next() {
		if clen != 0 {
			row, err := h.scan(rows, clen, tfmt)
			if err != nil {
				return err
			}
			// execute
			for _, sqlstr := range row {
				if err = h.Execute(ctx, w, res, stmt.FindPrefix(sqlstr, true, true, true), sqlstr); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// scan scans a row.
func (h *Handler) scan(rows *sql.Rows, clen int, tfmt string) ([]string, error) {
	// scan to []interface{}
	r := make([]interface{}, clen)
	for i := range r {
		r[i] = new(interface{})
	}
	if err := rows.Scan(r...); err != nil {
		return nil, err
	}
	// get conversion funcs
	cb, cm, cs, cd := ConvertBytes(), ConvertMap(), ConvertSlice(), ConvertDefault()
	row := make([]string, clen)
	for n, z := range r {
		j := z.(*interface{})
		switch x := (*j).(type) {
		case []byte:
			if x != nil {
				var err error
				if row[n], err = cb(x, tfmt); err != nil {
					return nil, err
				}
			}
		case string:
			row[n] = x
		case time.Time:
			row[n] = x.Format(tfmt)
		case fmt.Stringer:
			row[n] = x.String()
		case map[string]interface{}:
			if x != nil {
				var err error
				if row[n], err = cm(x); err != nil {
					return nil, err
				}
			}
		case []interface{}:
			if x != nil {
				var err error
				if row[n], err = cs(x); err != nil {
					return nil, err
				}
			}
		default:
			if x != nil {
				var err error
				if row[n], err = cd(x); err != nil {
					return nil, err
				}
			}
		}
	}
	return row, nil
}

// exec does a database exec.
func (h *Handler) exec(ctx context.Context, w io.Writer, _ metacmd.Option, typ, sqlstr string) error {
	res, err := h.db.ExecContext(ctx, sqlstr)
	if err != nil {
		_ = env.Set("ROW_COUNT", "0")
		return err
	}
	// get affected
	count, err := RowsAffected(res)
	if err != nil {
		_ = env.Set("ROW_COUNT", "0")
		return err
	}
	// print name
	fmt.Fprint(w, typ)
	// print count
	if count > 0 {
		fmt.Fprint(w, " ", count)
	}
	fmt.Fprintln(w)
	return env.Set("ROW_COUNT", strconv.FormatInt(count, 10))
}

// GetOutput gets the output writer.
func (h *Handler) GetOutput() io.Writer {
	if h.out == nil {
		return h.l.Stdout()
	}
	return h.out
}

// SetOutput sets the output writer.
func (h *Handler) SetOutput(o io.WriteCloser) {
	if h.out != nil {
		h.out.Close()
	}
	h.out = o
}
