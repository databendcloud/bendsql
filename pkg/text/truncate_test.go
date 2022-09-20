package text

import (
	"testing"
)

func TestTruncate(t *testing.T) {
	type args struct {
		max int
		s   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Short enough",
			args: args{
				max: 5,
				s:   "short",
			},
			want: "short",
		},
		{
			name: "Too short",
			args: args{
				max: 4,
				s:   "short",
			},
			want: "shor",
		},
		{
			name: "Japanese",
			args: args{
				max: 11,
				s:   "テストテストテストテスト",
			},
			want: "テストテ...",
		},
		{
			name: "Japanese filled",
			args: args{
				max: 11,
				s:   "aテストテストテストテスト",
			},
			want: "aテスト... ",
		},
		{
			name: "Chinese",
			args: args{
				max: 11,
				s:   "幫新舉報違章工廠新增編號",
			},
			want: "幫新舉報...",
		},
		{
			name: "Chinese filled",
			args: args{
				max: 11,
				s:   "a幫新舉報違章工廠新增編號",
			},
			want: "a幫新舉... ",
		},
		{
			name: "Korean",
			args: args{
				max: 11,
				s:   "프로젝트 내의",
			},
			want: "프로젝트...",
		},
		{
			name: "Korean filled",
			args: args{
				max: 11,
				s:   "a프로젝트 내의",
			},
			want: "a프로젝... ",
		},
		{
			name: "Emoji",
			args: args{
				max: 11,
				s:   "💡💡💡💡💡💡💡💡💡💡💡💡",
			},
			want: "💡💡💡💡...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Truncate(tt.args.max, tt.args.s); got != tt.want {
				t.Errorf("Truncate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncateColumn(t *testing.T) {
	type args struct {
		max int
		s   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "exactly minimum width",
			args: args{
				max: 5,
				s:   "short",
			},
			want: "short",
		},
		{
			name: "exactly minimum width with new line",
			args: args{
				max: 5,
				s:   "short\n",
			},
			want: "sh...",
		},
		{
			name: "less than minimum width",
			args: args{
				max: 4,
				s:   "short",
			},
			want: "shor",
		},
		{
			name: "less than minimum width with new line",
			args: args{
				max: 4,
				s:   "short\n",
			},
			want: "shor",
		},
		{
			name: "first line of multiple is short enough",
			args: args{
				max: 80,
				s:   "short\n\nthis is a new line",
			},
			want: "short...",
		},
		{
			name: "using Windows line endings",
			args: args{
				max: 80,
				s:   "short\r\n\r\nthis is a new line",
			},
			want: "short...",
		},
		{
			name: "using older MacOS line endings",
			args: args{
				max: 80,
				s:   "short\r\rthis is a new line",
			},
			want: "short...",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TruncateColumn(tt.args.max, tt.args.s); got != tt.want {
				t.Errorf("TruncateColumn() = %q, want %q", got, tt.want)
			}
		})
	}
}
