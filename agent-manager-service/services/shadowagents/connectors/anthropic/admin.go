// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package anthropic

import (
	"context"
	"net/url"

	"github.com/wso2/agent-manager/agent-manager-service/models"
	sa "github.com/wso2/agent-manager/agent-manager-service/services/shadowagents"
)

// listWorkspaces lists the organization's workspaces, the Default one
// included (anthropic.md §2.6: it is left out unless include_default=true).
func (s *scan) listWorkspaces(ctx context.Context, p *platform) ([]workspace, error) {
	var out []workspace
	q := url.Values{"include_default": {"true"}, "limit": {"1000"}}
	n, err := listByID(ctx, p.orgAPI, p.orgURL("/v1/organizations/workspaces"), q, nil, maxAdminPages, func(items []workspace) bool {
		for _, w := range items {
			if w.ID == "" {
				continue
			}
			out = append(out, w)
		}
		return true
	})
	s.calls.Record(p.call(callWorkspaces), n, err)
	return out, err
}

// listUsers reads the organization's members, to name the creators of API
// keys (anthropic.md §2.6b).
func (s *scan) listUsers(ctx context.Context, p *platform) {
	q := url.Values{"limit": {"1000"}}
	n, err := listByID(ctx, p.orgAPI, p.orgURL("/v1/organizations/users"), q, nil, maxAdminPages, func(items []user) bool {
		for _, u := range items {
			if u.ID != "" {
				s.users[u.ID] = u
			}
		}
		return true
	})
	s.calls.Record(p.call(callUsers), n, err)
}

// listKeys lists every API key, whatever its status, so a key that was
// disabled, archived or has expired is reported with that status
// (anthropic.md §2.5). Each key is a finding of kind api_key.
func (s *scan) listKeys(ctx context.Context, p *platform) {
	q := url.Values{"limit": {"1000"}}
	n, err := listByID(ctx, p.orgAPI, p.orgURL("/v1/organizations/api_keys"), q, nil, maxAdminPages, func(items []apiKey) bool {
		for _, k := range items {
			s.addKey(p, k)
		}
		return true
	})
	s.calls.Record(p.call(callAPIKeys), n, err)
}

func (s *scan) addKey(p *platform, k apiKey) {
	if k.ID == "" {
		return
	}
	ws := ""
	switch {
	case k.Scope != nil && k.Scope.Type == "workspace":
		ws = k.Scope.WorkspaceID
	case k.Scope == nil:
		ws = deref(k.WorkspaceID)
	}
	scope := p.orgScope()
	if ws != "" {
		scope = p.wsScope(ws)
	}
	createdAt, ok := parseTime(k.CreatedAt)
	owner := s.keyOwner(k)
	if ok {
		owner.CreatedAt = &createdAt
	}
	key := sa.Key{
		KeyID:        k.ID,
		Name:         sa.SanitizeName(k.Name),
		RedactedHint: deref(k.PartialKeyHint),
		Status:       k.Status,
		Scope:        scope,
		OwnerHint:    sa.MinimiseOwnerHint(owner),
	}
	if ok {
		key.CreatedAt = &createdAt
	}
	if i, seen := s.keyIndex[k.ID]; seen {
		s.keys[i] = key
	} else {
		s.keyIndex[k.ID] = len(s.keys)
		s.keys = append(s.keys, key)
	}
	s.keyWorkspace[k.ID] = ws

	created := s.findings.Get(models.ShadowKindAPIKey, k.ID)
	created.DisplayName = k.Name
	if created.DisplayName == "" {
		created.DisplayName = k.ID
	}
	created.Scope = scope
	created.State = k.Status
	created.OwnerHint = owner
	if ok {
		created.ProviderCreatedAt = &createdAt
	}
	created.AddKeyID(k.ID)
	created.Attributes["status"] = k.Status
	if ws != "" {
		created.Attributes["workspace"] = ws
	}
}

// keyOwner names the key's creator (created_by) or, when the creator is not
// recorded, the principal the key acts as. A user is resolved through the
// users list; a service account cannot be (its endpoints need an org:admin
// OAuth token), so only its ID is kept.
func (s *scan) keyOwner(k apiKey) models.ShadowOwnerHint {
	var id, typ, source string
	switch {
	case k.CreatedBy != nil && k.CreatedBy.ID != "":
		id, typ, source = k.CreatedBy.ID, k.CreatedBy.Type, callAPIKeys+" (created_by)"
	case k.Principal != nil && k.Principal.UserID != "":
		id, typ, source = k.Principal.UserID, "user", callAPIKeys+" (principal)"
	case k.Principal != nil && k.Principal.ServiceAccountID != "":
		id, typ, source = k.Principal.ServiceAccountID, "service_account", callAPIKeys+" (principal)"
	default:
		return models.ShadowOwnerHint{}
	}
	h := models.ShadowOwnerHint{Username: id, Type: typ, Source: source}
	if typ == "user" {
		if u, ok := s.users[id]; ok {
			h.Name, h.Email = u.Name, u.Email
			h.Source = source + " + " + callUsers
		}
	}
	return h
}
