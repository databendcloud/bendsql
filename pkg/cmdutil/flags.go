package cmdutil

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"strings"
)

type enumValue struct {
	string  *string
	options []string
}

func formatValuesForUsageDocs(values []string) string {
	return fmt.Sprintf("{%s}", strings.Join(values, "|"))
}

func (e *enumValue) Set(value string) error {
	if !isIncluded(value, e.options) {
		return fmt.Errorf("valid values are %s", formatValuesForUsageDocs(e.options))
	}
	*e.string = value
	return nil
}

func (e *enumValue) String() string {
	return *e.string
}

func (e *enumValue) Type() string {
	return "string"
}
func isIncluded(value string, opts []string) bool {
	for _, opt := range opts {
		if strings.EqualFold(opt, value) {
			return true
		}
	}
	return false
}

// StringEnumFlag defines a new string flag that only allows values listed in options.
func StringEnumFlag(cmd *cobra.Command, p *string, name, shorthand, defaultValue string, options []string, usage string) *pflag.Flag {
	*p = defaultValue
	val := &enumValue{string: p, options: options}
	f := cmd.Flags().VarPF(val, name, shorthand, fmt.Sprintf("%s: %s", usage, formatValuesForUsageDocs(options)))
	_ = cmd.RegisterFlagCompletionFunc(name, func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return options, cobra.ShellCompDirectiveNoFileComp
	})
	return f
}
