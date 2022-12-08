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

package auth

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/prompt"
	"github.com/pkg/errors"

	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/pkg/iostreams"

	"github.com/MakeNowJust/heredoc"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/spf13/cobra"
)

type ConfigureOptions struct {
	IO        *iostreams.IOStreams
	ApiClient func() (*api.APIClient, error)
	Config    config.Config
	Org       string
	Warehouse string
}

func NewCmdConfigure(f *cmdutil.Factory) *cobra.Command {
	opts := &ConfigureOptions{
		IO:        f.IOStreams,
		ApiClient: f.ApiClient,
	}
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Set your default org and using warehouse",
		Long:  "Set your default org and using warehouse",
		Example: heredoc.Doc(`
			# Set your default org and using warehouse with flag
			# NOTE: Using flag is faster than interactive shell
			$ bendsql auth configure --org ORG --warehouse WAREHOUSENAME

			# Set with interactive shell
			$ bendsql auth configure
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.GetConfig()
			if err != nil {
				return errors.Wrap(err, "new config failed")
			}

			apiClient, err := opts.ApiClient()
			if err != nil {
				return errors.Wrap(err, "new api client failed")
			}
			orgDtos, err := apiClient.ListOrgs()
			if err != nil {
				return errors.Wrap(err, "list orgs failed")
			}
			if opts.Org == "" {
				err = askForOrg(opts, orgDtos)
				if err != nil {
					return errors.Wrap(err, "ask for org failed")
				}
			}
			for _, org := range orgDtos {
				if org.OrgSlug == opts.Org {
					cfg.Org = org.OrgSlug
					cfg.Tenant = org.OrgTenantID
					cfg.Gateway = org.Gateway
					break
				}
			}

			warehouseDtos, err := apiClient.ListWarehouses()
			if err != nil {
				return errors.Wrap(err, "list warehouses failed")
			}
			if opts.Warehouse == "" {
				err = askForWarehouse(opts, warehouseDtos)
				if err != nil {
					return errors.Wrap(err, "ask for warehouse failed")
				}
			}
			for _, warehouse := range warehouseDtos {
				if warehouse.Name == opts.Warehouse {
					cfg.Warehouse = warehouse.Name
					break
				}
			}

			err = config.WriteConfig(cfg)
			if err != nil {
				return errors.Wrap(err, "write config failed")
			}
			fmt.Printf("configure success, current org is %s, current warehosue is %s\n", opts.Org, opts.Warehouse)
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.Org, "org", "", "org")
	cmd.Flags().StringVar(&opts.Warehouse, "warehouse", "", "warehouse")

	return cmd
}

func askForOrg(opts *ConfigureOptions, orgDtos []api.OrgMembershipDTO) error {
	var orgs []string
	for i := range orgDtos {
		orgs = append(orgs, orgDtos[i].OrgSlug)
	}
	err := prompt.SurveyAskOne(
		&survey.Select{
			Message: "Select your working org:",
			Options: orgs,
			Default: orgs[0],
			Description: func(value string, index int) string {
				return orgDtos[index].Description()
			},
		}, &opts.Org, survey.WithValidator(survey.Required))
	if err != nil {
		return errors.Wrap(err, "could not prompt")
	}
	return nil
}

func askForWarehouse(opts *ConfigureOptions, warehouseDtos []api.WarehouseStatusDTO) error {
	var warehouses []string
	for i := range warehouseDtos {
		warehouses = append(warehouses, warehouseDtos[i].Name)
	}
	err := prompt.SurveyAskOne(
		&survey.Select{
			Message: "Select your working warehouse:",
			Options: warehouses,
			Default: warehouses[0],
			Description: func(value string, index int) string {
				return warehouseDtos[index].Description()
			},
		}, &opts.Warehouse, survey.WithValidator(survey.Required))
	if err != nil {
		return errors.Wrap(err, "could not prompt")
	}
	return nil
}
