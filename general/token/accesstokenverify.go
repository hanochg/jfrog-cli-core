package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/auth/accesstoken"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	rootCertificateCall = "GET /access/api/v1/cert/root"
	tokenDetailsCall    = "GET /access/api/v1/tokens/me"
	readinessCall       = "GET /access/api/v1/system/readiness"
)

type TokenFormat string

const (
	TokenFormatJWT       TokenFormat = "JWT"
	TokenFormatReference TokenFormat = "Reference"
)

type AccessTokenVerifyResult struct {
	Valid   bool                   `json:"valid"`
	Error   string                 `json:"error,omitempty"`
	Format  TokenFormat            `json:"format,omitempty"`
	Header  *accesstoken.Header    `json:"header,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
	Types   []TokenType            `json:"types,omitempty"`
}

type accessClient interface {
	GetRootCertificate() (string, error)
	CheckReadiness() (int, error)
	GetOwnTokenDetails() (int, map[string]interface{}, error)
}

type AccessTokenVerifyCommand struct {
	serverDetails   *config.ServerDetails
	usageDetails    *config.ServerDetails
	token           string
	result          *AccessTokenVerifyResult
	now             func() time.Time
	newAccessClient func(*config.ServerDetails) (accessClient, error)
}

func NewAccessTokenVerifyCommand() *AccessTokenVerifyCommand {
	return &AccessTokenVerifyCommand{
		now: time.Now,
		newAccessClient: func(details *config.ServerDetails) (accessClient, error) {
			return rtUtils.CreateAccessServiceManager(details, false)
		},
	}
}

func (c *AccessTokenVerifyCommand) SetServerDetails(serverDetails *config.ServerDetails) *AccessTokenVerifyCommand {
	c.serverDetails = serverDetails
	c.usageDetails = withoutTokenRefresh(serverDetails)
	return c
}

// Usage reporting authenticates with these details; without the refresh tokens, it can't refresh or rewrite the profile mid-verification.
func withoutTokenRefresh(profile *config.ServerDetails) *config.ServerDetails {
	if profile == nil {
		return nil
	}
	details := *profile
	details.RefreshToken = ""
	details.ArtifactoryRefreshToken = ""
	details.DisableTokenRefresh = true
	return &details
}

func (c *AccessTokenVerifyCommand) SetToken(token string) *AccessTokenVerifyCommand {
	c.token = token
	return c
}

func (c *AccessTokenVerifyCommand) ServerDetails() (*config.ServerDetails, error) {
	return c.usageDetails, nil
}

func (c *AccessTokenVerifyCommand) CommandName() string {
	return "jf_access_token_verify"
}

func (c *AccessTokenVerifyCommand) Result() *AccessTokenVerifyResult {
	return c.result
}

func (c *AccessTokenVerifyCommand) Run() error {
	c.result = &AccessTokenVerifyResult{}
	if err := c.verify(); err != nil {
		c.result.Error = err.Error()
		return err
	}
	c.result.Valid = true
	return nil
}

func (c *AccessTokenVerifyCommand) verify() error {
	if !strings.Contains(c.token, ".") {
		return c.verifyReferenceToken()
	}
	return c.verifyJWT()
}

func (c *AccessTokenVerifyCommand) verifyJWT() error {
	parsed, err := accesstoken.ParseToken(c.token)
	if err != nil {
		return errorutils.CheckErrorf("failed to parse token: %s", err.Error())
	}
	c.result.Format = TokenFormatJWT
	c.result.Header = &parsed.Header
	c.result.Payload = parsed.Claims
	c.result.Types = IdentifyTokenTypes(parsed.Payload.Scp)
	if err = accesstoken.ValidateHeader(parsed.Header); err != nil {
		return err
	}
	client, err := c.createAccessClient()
	if err != nil {
		return err
	}
	if err = verifySignature(client, c.token); err != nil {
		return err
	}
	if err = accesstoken.ValidatePayloadFields(parsed.Payload); err != nil {
		return err
	}
	if err = accesstoken.ValidateExpiration(parsed.Payload, c.now()); err != nil {
		return err
	}
	status, err := client.CheckReadiness()
	return checkServerAnswer(status, err, readinessCall)
}

func (c *AccessTokenVerifyCommand) verifyReferenceToken() error {
	c.result.Format = TokenFormatReference
	client, err := c.createAccessClient()
	if err != nil {
		return err
	}
	details, err := getTokenDetails(client)
	var rejected tokenRejectedError
	if errors.As(err, &rejected) {
		return errorutils.CheckErrorf("reference %s", rejected.Error())
	}
	if err != nil {
		return err
	}
	c.result.Payload = details
	scope, _ := details["scope"].(string)
	c.result.Types = IdentifyTokenTypes(scope)
	return nil
}

func (c *AccessTokenVerifyCommand) createAccessClient() (accessClient, error) {
	if c.serverDetails == nil || c.serverDetails.Url == "" {
		return nil, errorutils.CheckErrorf("no JFrog server with a platform URL is configured; run 'jf config add'")
	}
	if warning := insecureConnectionWarning(c.serverDetails); warning != "" {
		log.Warn(warning)
	}
	return c.newAccessClient(tokenUnderInvestigationDetails(c.serverDetails, c.token))
}

func verifySignature(client accessClient, token string) error {
	rootCert, err := client.GetRootCertificate()
	if err != nil {
		return errorutils.CheckErrorf("failed to fetch root certificate (%s): %s", rootCertificateCall, err.Error())
	}
	key, err := accesstoken.ParseRootCertificate(rootCert)
	if err != nil {
		return err
	}
	return accesstoken.ValidateSignature(token, key)
}

type tokenRejectedError struct {
	status int
	call   string
}

func (e tokenRejectedError) Error() string {
	if e.status == http.StatusUnauthorized {
		return fmt.Sprintf("token revoked: status %d from %s", e.status, e.call)
	}
	return fmt.Sprintf("token rejected by Access server: status %d from %s", e.status, e.call)
}

func getTokenDetails(client accessClient) (map[string]interface{}, error) {
	status, details, err := client.GetOwnTokenDetails()
	if err = checkServerAnswer(status, err, tokenDetailsCall); err != nil {
		return nil, err
	}
	return details, nil
}

func checkServerAnswer(status int, err error, call string) error {
	switch {
	case err != nil:
		return errorutils.CheckErrorf("failed to check the token with Access server (%s): %s", call, err.Error())
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return errorutils.CheckError(tokenRejectedError{status: status, call: call})
	case status != http.StatusOK:
		return errorutils.CheckErrorf("unexpected response from Access server: status %d from %s", status, call)
	}
	return nil
}

// Starts from blank details: copying the profile would carry its refresh token, and the refresh hook
// could then send the profile's own token instead of the one under investigation.
func tokenUnderInvestigationDetails(profile *config.ServerDetails, token string) *config.ServerDetails {
	details := new(config.ServerDetails)
	details.Url = profile.Url
	details.ClientCertPath = profile.ClientCertPath
	details.ClientCertKeyPath = profile.ClientCertKeyPath
	details.AccessToken = token
	details.DisableTokenRefresh = true
	return details
}

func insecureConnectionWarning(details *config.ServerDetails) string {
	if !strings.HasPrefix(strings.ToLower(details.Url), "http://") {
		return ""
	}
	return fmt.Sprintf("The server URL %s uses http://, so the token is sent unencrypted, and the server's answers can't be proven to come from your JFrog server.", details.Url)
}
