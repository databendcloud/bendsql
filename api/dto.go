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

package api

import (
	"fmt"
	"time"
)

type AccountInfoDTO struct {
	ID              uint64    `json:"id"`
	Email           string    `json:"email"`
	Name            string    `json:"name"`
	State           string    `json:"state"`
	AvatarURL       string    `json:"avatarURL"`
	DefaultOrgSlug  string    `json:"defaultOrgSlug"`
	PasswordEnabled bool      `json:"passwordEnabled"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type OrgInfoDTO struct {
	Name         string    `json:"name"`
	MembersCount int64     `json:"memberCount"`
	TenantID     string    `json:"tenantID"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type WarehouseStatusDTO struct {
	Name           string `json:"id,omitempty"`
	ReadyInstances int64  `json:"readyInstances,omitempty"`
	Size           string `json:"size,omitempty"`
	State          string `json:"state,omitempty"`
	TotalInstances int64  `json:"totalInstances,omitempty"`
}

func (w WarehouseStatusDTO) String() string {
	return fmt.Sprintf("%s(%s):%s", w.Name, w.Size, w.State)
}

func (w WarehouseStatusDTO) Description() string {
	text := fmt.Sprintf("(%s)", w.Size)
	switch w.State {
	case "Running":
		text += "🟢 "
	case "Starting":
		text += "🟡 "
	case "Suspended":
		text += "⚪️ "
	default:
		text += fmt.Sprintf("🔴 %s", w.State)
	}
	return text
}

type OrgMembershipDTO struct {
	ID               uint64    `json:"id"`
	AccountID        uint64    `json:"accountID"`
	AccountName      string    `json:"accountName"`
	AccountEmail     string    `json:"accountEmail"`
	OrgAvatarURL     string    `json:"orgAvatarURL"`
	AccountAvatarURL string    `json:"accountAvatarURL"`
	OrgSlug          string    `json:"orgSlug"`
	OrgName          string    `json:"orgName"`
	OrgState         string    `json:"orgState"`
	OrgTenantID      string    `json:"tenantID"`
	Region           string    `json:"region"`
	Provider         string    `json:"provider"`
	Gateway          string    `json:"gateway"`
	MemberKind       string    `json:"memberKind"`
	State            string    `json:"state"`
	UpdatedAt        time.Time `json:"updatedAt"`
	CreatedAt        time.Time `json:"createdAt"`
}

func (o OrgMembershipDTO) String() string {
	return fmt.Sprintf("(%s)[%s]%s@%s:%s", o.OrgState, o.OrgName, o.OrgSlug, o.Provider, o.Region)
}

func (o OrgMembershipDTO) Description() string {
	return fmt.Sprintf("(%s)[%s]@%s:%s", o.OrgState, o.OrgName, o.Provider, o.Region)
}
