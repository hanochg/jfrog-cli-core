package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const testUserSub = "jfac@01ftqhpvg3kn760kg8qbt411qy/users/admin"

func TestIdentify_SingleScope(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  TokenType
	}{
		{AdminScope, TokenTypeAdmin},
		{"applied-permissions/user", TokenTypeIdentity},
		{"applied-permissions/user:piggy", TokenTypeIdentity},
		{"member-of-groups:*", TokenTypeIdentity},
		{"applied-permissions/groups:readers,writers", TokenTypeGroups},
		{"member-of-groups:readers,qa", TokenTypeGroups},
		{"applied-permissions/roles:proj1:developer,viewer", TokenTypeRoles},
		{"applied-permissions/entitlements:/follow-ext/", TokenTypeEntitlements},
		{"system:metrics:r", TokenTypeScoped},
		{"artifact:generic-local/foo/bar.txt:r,w", TokenTypeScoped},
		{"repo:my-repo@proj1:r,w,d", TokenTypeScoped},
		{"*:*:*", TokenTypeScoped},
		{"api:*", TokenTypeScoped},
		{"internal:x:r", TokenTypeInternal},
		{"internal:impersonation/user/laUser", TokenTypeInternal},
		{"internal:connect-agent-trust/devices:x", TokenTypeInternal},
		{"something-not-matching-any-rule", TokenTypeUnknown},
		{"applied-permissions/group:readers", TokenTypeUnknown},
		{"applied-permissions/role:proj1:developer", TokenTypeUnknown},
		{"applied-permissions/users", TokenTypeUnknown},
		{"ui:*", TokenTypeUnknown},
		{"api:ha-propagate", TokenTypeUnknown},
		{"internal-sync", TokenTypeUnknown},
		{"jfrt@1b161a7c:admin", TokenTypeUnknown},
		{"system:metrics:q", TokenTypeUnknown},
	} {
		assert.Equal(t, []TokenType{tc.want}, IdentifyTokenTypes(tc.scope), tc.scope)
	}
}

func TestIdentify_QuotedScopes(t *testing.T) {
	for _, tc := range []struct {
		scp  string
		want []TokenType
	}{
		{`applied-permissions/groups:group_1,"group 2"`, []TokenType{TokenTypeGroups}},
		{`"applied-permissions/groups:group_1, group 2"`, []TokenType{TokenTypeGroups}},
		{`applied-permissions/groups:"group_1, group 2" applied-permissions/admin`, []TokenType{TokenTypeGroups, TokenTypeAdmin}},
		{`applied-permissions/roles:proj1:"lead dev","qa"`, []TokenType{TokenTypeRoles}},
		{`artifact:"generic-local/foo/bar baz/bla.txt":r,w`, []TokenType{TokenTypeScoped}},
		{`"artifact:generic-local/foo/bar baz/bla.txt:r,w"`, []TokenType{TokenTypeScoped}},
		{`"artifact:myrepo/foo\"bar.txt:r"`, []TokenType{TokenTypeScoped}},
		{`"internal:x:r"`, []TokenType{TokenTypeInternal}},
	} {
		assert.Equal(t, tc.want, IdentifyTokenTypes(tc.scp), tc.scp)
	}
}

func TestIdentify_MultipleScopes(t *testing.T) {
	for _, tc := range []struct {
		scp  string
		want []TokenType
	}{
		{"applied-permissions/user system:metrics:r", []TokenType{TokenTypeIdentity, TokenTypeScoped}},
		{"internal:x:r " + AdminScope, []TokenType{TokenTypeInternal, TokenTypeAdmin}},
		{AdminScope + " internal:x:r internal:y:w", []TokenType{TokenTypeAdmin, TokenTypeInternal}},
		{"*:*:* system:*:*", []TokenType{TokenTypeScoped}},
		{"internal:connect-agent-trust/pairing:x", []TokenType{TokenTypeConnectPairing, TokenTypeInternal}},
		{"internal:connect-agent-trust/device:x", []TokenType{TokenTypeConnectDevice, TokenTypeInternal}},
		{"internal:connect-agent-trust/device:x internal:connect-agent-trust/pairing:y", []TokenType{TokenTypeConnectDevice, TokenTypeConnectPairing, TokenTypeInternal}},
		{"internal:connect-agent-trust/device:x applied-permissions/user", []TokenType{TokenTypeConnectDevice, TokenTypeIdentity, TokenTypeInternal}},
		{"internal:connect-agent-trust/device:x internal:x:r", []TokenType{TokenTypeConnectDevice, TokenTypeInternal}},
		{"applied-permissions/roles:proj1:developer applied-permissions/groups:readers member-of-groups:qa", []TokenType{TokenTypeRoles, TokenTypeGroups}},
		{"ui:* api:*", []TokenType{TokenTypeUnknown, TokenTypeScoped}},
	} {
		assert.Equal(t, tc.want, IdentifyTokenTypes(tc.scp), tc.scp)
	}
}

func TestIdentify_NoScopes(t *testing.T) {
	for _, scp := range []string{"", "   ", `  ""  `} {
		assert.Equal(t, []TokenType{TokenTypeUnknown}, IdentifyTokenTypes(scp), scp)
	}
}

func TestIdentify_AtcScopes(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  []TokenType
	}{
		{"applied-permissions/user", []TokenType{TokenTypeIdentity}},
		{AdminScope, []TokenType{TokenTypeAdmin}},
		{GroupsScopePrefix + "readers" + " " + AdminScope, []TokenType{TokenTypeGroups, TokenTypeAdmin}},
		{"system:metrics:r", []TokenType{TokenTypeScoped}},
	} {
		assert.Equal(t, tc.want, IdentifyTokenTypes(tc.scope), tc.scope)
	}
}
