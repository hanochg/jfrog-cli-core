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
	TokenTypeScoped         TokenType = "Scoped Token"
	TokenTypeConnectPairing TokenType = "Connect Pairing Token"
	TokenTypeConnectDevice  TokenType = "Connect Device Token"
	TokenTypeInternal       TokenType = "Internal Token"
	TokenTypeUnknown        TokenType = "Unknown Token Type"

	userScope                 = "applied-permissions/user"
	rolesScopePrefix          = "applied-permissions/roles:"
	connectPairingScopePrefix = "internal:connect-agent-trust/pairing:"
	connectDeviceScopePrefix  = "internal:connect-agent-trust/device:"
	internalScopePrefix       = "internal:"
)

var (
	serviceSubjectPattern = regexp.MustCompile(`^[a-z]{4,6}@[a-zA-Z0-9*]+(/nodes/[^/]+)?$`)
	scopedTokenPattern    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*:.+:[a-zA-Z*]+$`)
)

// Connect tokens are internal but reported by name. Any other internal signal hides the remaining types behind a single Internal Token.
func IdentifyTokenTypes(t *accesstoken.ParsedToken) []TokenType {
	var types []TokenType
	for _, scope := range t.Payload.Scopes() {
		if tokenType := classifyScope(scope); !slices.Contains(types, tokenType) {
			types = append(types, tokenType)
		}
	}
	if !hasInternalSubject(t) && !slices.Contains(types, TokenTypeInternal) {
		return types
	}
	var visible []TokenType
	for _, tokenType := range types {
		if tokenType == TokenTypeConnectPairing || tokenType == TokenTypeConnectDevice {
			visible = append(visible, tokenType)
		}
	}
	return append(visible, TokenTypeInternal)
}

func hasInternalSubject(t *accesstoken.ParsedToken) bool {
	return serviceSubjectPattern.MatchString(t.Payload.Sub) || (t.ParsedExt != nil && t.ParsedExt.Sid != "")
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
	case scope == userScope:
		return TokenTypeIdentity
	case strings.HasPrefix(scope, GroupsScopePrefix):
		return TokenTypeGroups
	case strings.HasPrefix(scope, rolesScopePrefix):
		return TokenTypeRoles
	case scopedTokenPattern.MatchString(scope):
		return TokenTypeScoped
	default:
		return TokenTypeUnknown
	}
}
