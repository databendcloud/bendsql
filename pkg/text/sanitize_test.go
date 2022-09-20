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

package text

import "testing"

func TestReplaceExcessiveWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no replacements",
			input: "one two three",
			want:  "one two three",
		},
		{
			name:  "whitespace b-gone",
			input: "\n  one\n\t  two  three\r\n  ",
			want:  "one two three",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReplaceExcessiveWhitespace(tt.input); got != tt.want {
				t.Errorf("ReplaceExcessiveWhitespace() = %v, want %v", got, tt.want)
			}
		})
	}
}
