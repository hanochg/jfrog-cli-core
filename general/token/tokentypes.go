package token

import (
	"regexp"
	"slices"
	"strings"

	"github.com/jfrog/jfrog-client-go/auth/accesstoken"
)

type TokenType string

const (
	TokenTypeAdmin          TokenType = "Admin Token"
	TokenTypeIdentity       TokenType = "Identity Token"
	TokenTypeGroups         TokenType = "Applied Permissions Groups Token"
	TokenTypeRoles          TokenType = "Applied Permissions Roles Token"
	TokenTypeEntitlements   TokenType = "Applied Permissions Entitlements Token"
	TokenTypeScoped         TokenType = "Scoped Token"
	TokenTypeConnectPairing TokenType = "Connect Pairing Token"
	TokenTypeConnectDevice  TokenType = "Connect Device Token"
	TokenTypeInternal       TokenType = "Internal Token"
	TokenTypeUnknown        TokenType = "Unknown Token Type"

	userScope                 = "applied-permissions/user"
	userScopePrefix           = userScope + ":"
	rolesScopePrefix          = "applied-permissions/roles:"
	entitlementsScopePrefix   = "applied-permissions/entitlements:"
	legacyGroupsScopePrefix   = "member-of-groups:"
	legacyUserScope           = legacyGroupsScopePrefix + "*"
	legacyApiScope            = "api:*"
	connectPairingScopePrefix = "internal:connect-agent-trust/pairing:"
	connectDeviceScopePrefix  = "internal:connect-agent-trust/device:"
	internalScopePrefix       = "internal:"
)

var resourceScopePattern = regexp.MustCompile(`^(?:[a-zA-Z_-]+|\*):(?:\*|[^:/@]+(?:@[^:/]+)?(?:/[^:]+)?):(?:\*|[rwdamsx](?:,[rwdamsx])*)$`)

func IdentifyTokenTypes(scp string) []TokenType {
	payload := accesstoken.Payload{Scp: scp}
	var types []TokenType
	for _, scope := range payload.Scopes() {
		if tokenType := classifyScope(accesstoken.UnquoteScope(scope)); !slices.Contains(types, tokenType) {
			types = append(types, tokenType)
		}
	}
	if len(types) == 0 {
		return []TokenType{TokenTypeUnknown}
	}
	if (slices.Contains(types, TokenTypeConnectPairing) || slices.Contains(types, TokenTypeConnectDevice)) && !slices.Contains(types, TokenTypeInternal) {
		types = append(types, TokenTypeInternal)
	}
	return types
}

func classifyScope(scope string) TokenType {
	switch {
	case strings.HasPrefix(scope, connectPairingScopePrefix):
		return TokenTypeConnectPairing
	case strings.HasPrefix(scope, connectDeviceScopePrefix):
		return TokenTypeConnectDevice
	case strings.HasPrefix(scope, internalScopePrefix):
		return TokenTypeInternal
	case scope == AdminScope:
		return TokenTypeAdmin
	case scope == userScope, strings.HasPrefix(scope, userScopePrefix), scope == legacyUserScope:
		return TokenTypeIdentity
	case strings.HasPrefix(scope, GroupsScopePrefix), strings.HasPrefix(scope, legacyGroupsScopePrefix):
		return TokenTypeGroups
	case strings.HasPrefix(scope, rolesScopePrefix):
		return TokenTypeRoles
	case strings.HasPrefix(scope, entitlementsScopePrefix):
		return TokenTypeEntitlements
	case scope == legacyApiScope, resourceScopePattern.MatchString(scope):
		return TokenTypeScoped
	default:
		return TokenTypeUnknown
	}
}
