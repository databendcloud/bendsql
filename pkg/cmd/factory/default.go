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

package factory

import (
	"github.com/databendcloud/bendsql/api"
	"github.com/databendcloud/bendsql/internal/config"
	"github.com/databendcloud/bendsql/pkg/cmdutil"
	"github.com/databendcloud/bendsql/pkg/iostreams"
)

func New(appVersion string) *cmdutil.Factory {
	f := &cmdutil.Factory{
		ExecutableName: "bendsql",
		ApiClient:      httpClientFunc(),
		Config:         configFunc(),
	}

	f.IOStreams = ioStreams(f)

	return f
}

func ioStreams(f *cmdutil.Factory) *iostreams.IOStreams {
	io := iostreams.System()

	return io
}

func configFunc() func() (config.Configer, error) {
	var cachedConfig config.Configer
	var configError error
	return func() (config.Configer, error) {
		if cachedConfig != nil || configError != nil {
			return cachedConfig, configError
		}
		cachedConfig, configError = config.NewConfig()
		return cachedConfig, configError
	}
}

func httpClientFunc() func() (*api.APIClient, error) {
	return func() (*api.APIClient, error) {
		return api.NewApiClient(), nil
	}
}
