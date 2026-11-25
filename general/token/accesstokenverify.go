package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-client-go/access/services"
	"github.com/jfrog/jfrog-client-go/auth/accesstoken"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

const (
	rootCertificateCall    = "GET /access/api/v1/cert/root"
	tokenDetailsCall       = "GET /access/api/v1/tokens/me"
	artifactoryServiceType = "jfrt"
	artifactoryVersionCall = "GET /artifactory/api/system/version"
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
	GetArtifactoryVersion() (*services.ArtifactoryVersion, error)
	GetOwnTokenDetails() (*services.TokenDetails, error)
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
	_, err = client.GetArtifactoryVersion()
	rejected, isRejected := asAuthResponseError(err)
	if audiences := parsed.Payload.AudAsStringSlice(); isRejected && !audienceIncludesArtifactory(audiences) {
		return errorutils.CheckErrorf("token rejected by Artifactory: status %d from %s. The token's audience (%s) doesn't include Artifactory, which is the likely reason; the token may still be valid for that audience", rejected.StatusCode, artifactoryVersionCall, strings.Join(audiences, " "))
	}
	if isRejected {
		return errorutils.CheckErrorf("token revoked: status %d from %s", rejected.StatusCode, artifactoryVersionCall)
	}
	return serverError(err, artifactoryVersionCall)
}

func audienceIncludesArtifactory(audiences []string) bool {
	for _, entry := range audiences {
		for _, audience := range strings.Fields(entry) {
			if service, _, _ := strings.Cut(audience, "@"); service == "*" || service == artifactoryServiceType {
				return true
			}
		}
	}
	return false
}

func (c *AccessTokenVerifyCommand) verifyReferenceToken() error {
	c.result.Format = TokenFormatReference
	client, err := c.createAccessClient()
	if err != nil {
		return err
	}
	details, err := client.GetOwnTokenDetails()
	if rejected, isRejected := asAuthResponseError(err); isRejected && rejected.StatusCode == http.StatusUnauthorized {
		return errorutils.CheckErrorf("reference token revoked: status %d from %s", rejected.StatusCode, tokenDetailsCall)
	} else if isRejected {
		return errorutils.CheckErrorf("reference token rejected by the JFrog server: status %d from %s", rejected.StatusCode, tokenDetailsCall)
	}
	if err = serverError(err, tokenDetailsCall); err != nil {
		return err
	}
	if c.result.Payload, err = detailsAsPayload(details); err != nil {
		return err
	}
	c.result.Types = IdentifyTokenTypes(details.Scope)
	return nil
}

func (c *AccessTokenVerifyCommand) createAccessClient() (accessClient, error) {
	if c.serverDetails == nil || c.serverDetails.Url == "" {
		return nil, errorutils.CheckErrorf("no JFrog server with a platform URL is configured; run 'jf config add'")
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

func asAuthResponseError(err error) (*services.AuthResponseError, bool) {
	var rejected *services.AuthResponseError
	return rejected, errors.As(err, &rejected)
}

func serverError(err error, call string) error {
	var responseErr *errorutils.HttpResponseError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &responseErr):
		message := fmt.Sprintf("unexpected response from the JFrog server: status %d from %s", responseErr.StatusCode, call)
		if body := strings.Join(strings.Fields(string(responseErr.Body)), " "); body != "" {
			message += ": " + body
		}
		return errorutils.CheckError(errors.New(message))
	default:
		return errorutils.CheckErrorf("failed to check the token with the JFrog server (%s): %s", call, err.Error())
	}
}

func detailsAsPayload(details *services.TokenDetails) (map[string]interface{}, error) {
	data, err := json.Marshal(details)
	if err != nil {
		return nil, errorutils.CheckError(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	payload := map[string]interface{}{}
	return payload, errorutils.CheckError(decoder.Decode(&payload))
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
