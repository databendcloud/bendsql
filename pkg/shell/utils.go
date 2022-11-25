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
	"bufio"
	"io"
	"log"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/xo/usql/drivers/metadata"
	"github.com/xo/usql/env"
)

// lineterm is the end of line terminal.
var lineterm string

func init() {
	lineterm = "\n"
	if runtime.GOOS == "windows" {
		lineterm = "\r\n"
	}
}

// empty reports whether s contains at least one printable, non-space character.
func empty(s string) bool {
	i := strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsPrint(r) && !unicode.IsSpace(r)
	})
	return i == -1
}

var ansiRE = regexp.MustCompile(`\x1b[[0-9]+([:;][0-9]+)*m`)

// lastcolor returns the last defined color in s, if any.
func lastcolor(s string) string {
	if i := strings.LastIndex(s, "\n"); i != -1 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "\x1b[0m"); i != -1 {
		s = s[i+4:]
	}
	return strings.Join(ansiRE.FindAllString(s, -1), "")
}

func readerOpts() []metadata.ReaderOption {
	var opts []metadata.ReaderOption
	envs := env.All()
	if envs["ECHO_HIDDEN"] == "on" || envs["ECHO_HIDDEN"] == "noexec" {
		if envs["ECHO_HIDDEN"] == "noexec" {
			opts = append(opts, metadata.WithDryRun(true))
		}
		opts = append(
			opts,
			metadata.WithLogger(log.New(os.Stdout, "DEBUG: ", log.LstdFlags)),
			metadata.WithTimeout(30*time.Second),
		)
	}
	return opts
}

// peekEnding peeks to see if the next successive bytes in r is \n or \r\n,
// writing to w if it is. Does not advance r if the next bytes are not \n or
// \r\n.
func peekEnding(w io.Writer, r *bufio.Reader) error {
	// peek first byte
	buf, err := r.Peek(1)
	switch {
	case err != nil && err != io.EOF:
		return err
	case err == nil && buf[0] == '\n':
		if _, rerr := r.ReadByte(); err != nil && err != io.EOF {
			return rerr
		}
		_, werr := w.Write([]byte{'\n'})
		return werr
	case err == nil && buf[0] != '\r':
		return nil
	}
	// peek second byte
	buf, err = r.Peek(1)
	switch {
	case err != nil && err != io.EOF:
		return err
	case err == nil && buf[0] != '\n':
		return nil
	}
	if _, rerr := r.ReadByte(); err != nil && err != io.EOF {
		return rerr
	}
	_, werr := w.Write([]byte{'\n'})
	return werr
}

// grab grabs i from r, or returns 0 if i >= end.
func grab(r []rune, i, end int) rune {
	if i < end {
		return r[i]
	}
	return 0
}
