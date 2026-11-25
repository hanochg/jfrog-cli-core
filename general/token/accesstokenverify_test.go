package token

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-client-go/access/services"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	GenerateTestCert = generateTestCert
	SignToken        = signToken
	ValidHeader      = validHeader
	ValidClaims      = validClaims
)

var testNow = time.Unix(1_800_000_000, 0)

func generateTestCert(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(certDER), key
}

func signToken(t *testing.T, key *rsa.PrivateKey, header, claims map[string]interface{}) string {
	t.Helper()
	encode := func(v interface{}) string {
		data, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func validHeader() map[string]interface{} {
	return map[string]interface{}{"alg": "RS256", "typ": "JWT", "ver": "2", "kid": "test-kid"}
}

func validClaims(now time.Time) map[string]interface{} {
	return map[string]interface{}{
		"jti": "test-jti",
		"sub": testUserSub,
		"aud": "*@*",
		"scp": "applied-permissions/user",
		"iss": "jfac@01ftqhpvg3kn760kg8qbt411qy",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"ext": `{"revocable":"true"}`,
	}
}

type fakeAccessClient struct {
	cert                    string
	rootErr                 error
	status                  int
	details                 *services.TokenDetails
	detailsErr              error
	rootCalls               int
	detailsCalls            int
	version                 int
	versionErr              error
	artifactoryVersionCalls int
	errorBody               string
}

func fakeResponseError(status int, api string, body string) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return &services.TokenRejectedError{StatusCode: status, Api: api}
	default:
		return &errorutils.HttpResponseError{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Body: []byte(body)}
	}
}

func (f *fakeAccessClient) GetArtifactoryVersion() (*services.ArtifactoryVersion, error) {
	f.artifactoryVersionCalls++
	if f.versionErr != nil {
		return nil, f.versionErr
	}
	if err := fakeResponseError(f.version, "artifactory/api/system/version", f.errorBody); err != nil {
		return nil, err
	}
	return &services.ArtifactoryVersion{Version: "7.179.0"}, nil
}

func (f *fakeAccessClient) GetRootCertificate() (string, error) {
	f.rootCalls++
	return f.cert, f.rootErr
}

func (f *fakeAccessClient) GetOwnTokenDetails() (*services.TokenDetails, error) {
	f.detailsCalls++
	if f.detailsErr != nil {
		return nil, f.detailsErr
	}
	if err := fakeResponseError(f.status, "api/v1/tokens/me", f.errorBody); err != nil {
		return nil, err
	}
	return f.details, nil
}

func newTestCommand(token string, fake *fakeAccessClient) *AccessTokenVerifyCommand {
	cmd := NewAccessTokenVerifyCommand().SetServerDetails(&config.ServerDetails{Url: "https://jpd.example/"}).SetToken(token)
	cmd.now = func() time.Time { return testNow }
	cmd.newAccessClient = func(*config.ServerDetails) (accessClient, error) { return fake, nil }
	return cmd
}

func validSetup(t *testing.T) (*rsa.PrivateKey, *fakeAccessClient) {
	certB64, key := generateTestCert(t)
	details := &services.TokenDetails{TokenId: "id-1", Subject: testUserSub, Scope: "applied-permissions/user"}
	return key, &fakeAccessClient{cert: certB64, status: http.StatusOK, details: details, version: http.StatusOK}
}

func TestVerify_ValidIdentityToken(t *testing.T) {
	key, fake := validSetup(t)
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	require.NoError(t, cmd.Run())
	assert.True(t, cmd.Result().Valid)
	assert.Equal(t, []TokenType{TokenTypeIdentity}, cmd.Result().Types)
	assert.Equal(t, TokenFormatJWT, cmd.Result().Format)
	assert.Equal(t, 1, fake.artifactoryVersionCalls)
	assert.Zero(t, fake.detailsCalls)
}

func TestVerify_InvalidHeader_NoNetworkCalls(t *testing.T) {
	key, fake := validSetup(t)
	header := validHeader()
	header["ver"] = "1"
	cmd := newTestCommand(signToken(t, key, header, validClaims(testNow)), fake)
	assert.ErrorContains(t, cmd.Run(), `expected ver "2"`)
	assert.Zero(t, fake.rootCalls+fake.artifactoryVersionCalls+fake.detailsCalls)
	assert.NotNil(t, cmd.Result().Payload)
}

func TestVerify_NoConfiguredServer(t *testing.T) {
	key, fake := validSetup(t)
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	cmd.SetServerDetails(&config.ServerDetails{})
	assert.ErrorContains(t, cmd.Run(), "no JFrog server")
	assert.NotNil(t, cmd.Result().Payload)
	assert.Zero(t, fake.rootCalls)
}

func TestVerify_BadSignature_TokenNotSentToServer(t *testing.T) {
	_, fake := validSetup(t)
	_, otherKey := generateTestCert(t)
	cmd := newTestCommand(signToken(t, otherKey, validHeader(), validClaims(testNow)), fake)
	assert.ErrorContains(t, cmd.Run(), "invalid signature")
	assert.Zero(t, fake.artifactoryVersionCalls+fake.detailsCalls)
}

func TestVerify_MissingSub_BeforeServerCheck(t *testing.T) {
	key, fake := validSetup(t)
	claims := validClaims(testNow)
	delete(claims, "sub")
	cmd := newTestCommand(signToken(t, key, validHeader(), claims), fake)
	assert.ErrorContains(t, cmd.Run(), "missing required field: sub")
	assert.Zero(t, fake.artifactoryVersionCalls+fake.detailsCalls)
}

func TestVerify_Expired_BeforeServerCheck(t *testing.T) {
	key, fake := validSetup(t)
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow.Add(-2*time.Hour))), fake)
	assert.ErrorContains(t, cmd.Run(), "token expired at")
	assert.Zero(t, fake.artifactoryVersionCalls+fake.detailsCalls)
	assert.False(t, cmd.Result().Valid)
	assert.Equal(t, []TokenType{TokenTypeIdentity}, cmd.Result().Types)
}

func TestVerify_NoExpiry_Valid(t *testing.T) {
	key, fake := validSetup(t)
	claims := validClaims(testNow)
	delete(claims, "exp")
	assert.NoError(t, newTestCommand(signToken(t, key, validHeader(), claims), fake).Run())
}

func TestVerify_RootCertFetchFails(t *testing.T) {
	key, fake := validSetup(t)
	fake.rootErr = errors.New("boom")
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	assert.ErrorContains(t, cmd.Run(), "GET /access/api/v1/cert/root")
}

func TestVerify_ServerRejectsJWT(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusUnauthorized: "token revoked: status 401 from GET /artifactory/api/system/version",
		http.StatusForbidden:    "token revoked: status 403 from GET /artifactory/api/system/version",
	} {
		key, fake := validSetup(t)
		fake.version = status
		cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
		assert.EqualError(t, cmd.Run(), want)
		assert.False(t, cmd.Result().Valid)
		assert.Equal(t, TokenFormatJWT, cmd.Result().Format)
		assert.NotEmpty(t, cmd.Result().Payload)
		assert.Equal(t, []TokenType{TokenTypeIdentity}, cmd.Result().Types)
	}
}

func TestVerify_ArtifactoryRejectsTokenOutsideItsAudience(t *testing.T) {
	for _, tc := range []struct {
		aud  interface{}
		want string
	}{
		{"jfxr@*", "token rejected by Artifactory: status 401 from GET /artifactory/api/system/version. The token's audience (jfxr@*) doesn't include Artifactory"},
		{[]interface{}{"jfxr@01h", "jfmc@*"}, "The token's audience (jfxr@01h jfmc@*) doesn't include Artifactory"},
		{"*@*", "token revoked: status 401"},
		{"jfrt@*", "token revoked: status 401"},
		{"jfrt@01h jfxr@*", "token revoked: status 401"},
		{[]interface{}{"jfxr@*", "jfrt@01h"}, "token revoked: status 401"},
		{"*", "token revoked: status 401"},
	} {
		key, fake := validSetup(t)
		fake.version = http.StatusUnauthorized
		claims := validClaims(testNow)
		claims["aud"] = tc.aud
		cmd := newTestCommand(signToken(t, key, validHeader(), claims), fake)
		assert.ErrorContains(t, cmd.Run(), tc.want, tc.aud)
	}
}

func TestVerify_ServerUnexpectedStatus(t *testing.T) {
	key, fake := validSetup(t)
	fake.version = http.StatusServiceUnavailable
	fake.errorBody = "{\n  \"errors\": [{\"message\": \"maintenance\"}]\n}"
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	assert.EqualError(t, cmd.Run(), `unexpected response from the JFrog server: status 503 from GET /artifactory/api/system/version: { "errors": [{"message": "maintenance"}] }`)
}

func TestVerify_ServerCallFails(t *testing.T) {
	key, fake := validSetup(t)
	fake.versionErr = errors.New("connection refused")
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	assert.ErrorContains(t, cmd.Run(), "failed to check the token with the JFrog server (GET /artifactory/api/system/version): connection refused")
}

func TestVerify_ReferenceToken_Valid(t *testing.T) {
	_, fake := validSetup(t)
	cmd := newTestCommand("opaqueReferenceValue", fake)
	require.NoError(t, cmd.Run())
	result := cmd.Result()
	assert.True(t, result.Valid)
	assert.Equal(t, TokenFormatReference, result.Format)
	assert.Equal(t, map[string]interface{}{"token_id": "id-1", "subject": testUserSub, "scope": "applied-permissions/user"}, result.Payload)
	assert.Nil(t, result.Header)
	assert.Equal(t, []TokenType{TokenTypeIdentity}, result.Types)
	assert.Zero(t, fake.rootCalls+fake.artifactoryVersionCalls)
	assert.Equal(t, 1, fake.detailsCalls)
}

func TestVerify_ReferenceToken_Rejected(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusUnauthorized: "reference token revoked: status 401 from GET /access/api/v1/tokens/me",
		http.StatusForbidden:    "reference token rejected by the JFrog server: status 403 from GET /access/api/v1/tokens/me",
	} {
		_, fake := validSetup(t)
		fake.status = status
		cmd := newTestCommand("opaqueReferenceValue", fake)
		assert.EqualError(t, cmd.Run(), want)
		assert.False(t, cmd.Result().Valid)
		assert.Equal(t, TokenFormatReference, cmd.Result().Format)
		assert.Nil(t, cmd.Result().Payload)
		assert.Nil(t, cmd.Result().Types)
	}
}

func TestVerify_ReferenceToken_ServerFailures(t *testing.T) {
	_, fake := validSetup(t)
	fake.status = http.StatusServiceUnavailable
	assert.ErrorContains(t, newTestCommand("opaqueReferenceValue", fake).Run(), "unexpected response from the JFrog server: status 503")

	_, fake = validSetup(t)
	fake.detailsErr = errors.New("connection refused")
	assert.ErrorContains(t, newTestCommand("opaqueReferenceValue", fake).Run(), "failed to check the token with the JFrog server")

	_, fake = validSetup(t)
	cmd := newTestCommand("opaqueReferenceValue", fake)
	cmd.SetServerDetails(&config.ServerDetails{})
	assert.ErrorContains(t, cmd.Run(), "no JFrog server")
	assert.Zero(t, fake.artifactoryVersionCalls+fake.detailsCalls)
}

func TestVerify_TypesComeFromScopesOnly(t *testing.T) {
	for _, tc := range []struct {
		sub, scp, ext string
		want          []TokenType
	}{
		{"jfrt@01ftqhpvg3kn760kg8qbt411qy", AdminScope, `{"revocable":"true"}`, []TokenType{TokenTypeAdmin}},
		{"jfrt@01ftqhpvg3kn760kg8qbt411qy/nodes/n1", "api:*", `{"revocable":"true"}`, []TokenType{TokenTypeScoped}},
		{"jffe@000/users/admin", "applied-permissions/groups:readers", `{"sid":"s1","revocable":true}`, []TokenType{TokenTypeGroups}},
		{"jffe@000", "internal:impersonation/user/admin " + AdminScope, `{"sid":"s1"}`, []TokenType{TokenTypeInternal, TokenTypeAdmin}},
	} {
		key, fake := validSetup(t)
		claims := validClaims(testNow)
		claims["sub"], claims["scp"], claims["ext"] = tc.sub, tc.scp, tc.ext
		cmd := newTestCommand(signToken(t, key, validHeader(), claims), fake)
		require.NoError(t, cmd.Run(), tc.sub)
		assert.Equal(t, tc.want, cmd.Result().Types, tc.sub)
	}
}

func TestVerify_ReferenceToken_TypesFromServerDetails(t *testing.T) {
	for _, tc := range []struct {
		details *services.TokenDetails
		want    []TokenType
	}{
		{&services.TokenDetails{Subject: "jfrt@01h", Scope: AdminScope}, []TokenType{TokenTypeAdmin}},
		{&services.TokenDetails{Subject: "jfrt@01h", Scope: `internal:x:r "applied-permissions/groups:group 1"`}, []TokenType{TokenTypeInternal, TokenTypeGroups}},
		{&services.TokenDetails{Subject: "my_token", Scope: GroupsScopePrefix + "readers"}, []TokenType{TokenTypeGroups}},
		{&services.TokenDetails{TokenId: "id-1"}, []TokenType{TokenTypeUnknown}},
		{&services.TokenDetails{TokenId: "id-1", Scope: " "}, []TokenType{TokenTypeUnknown}},
	} {
		_, fake := validSetup(t)
		fake.details = tc.details
		cmd := newTestCommand("opaqueReferenceValue", fake)
		require.NoError(t, cmd.Run())
		assert.Equal(t, tc.want, cmd.Result().Types, tc.details)
	}
}

func TestVerify_MalformedJWT_NoReferenceTokenHint(t *testing.T) {
	for _, raw := range []string{"a.b.c", "abc.def", "a.b.c.d"} {
		_, fake := validSetup(t)
		err := newTestCommand(raw, fake).Run()
		assert.ErrorContains(t, err, "failed to parse token", raw)
		assert.NotContains(t, err.Error(), "reference token", raw)
		assert.Zero(t, fake.rootCalls+fake.artifactoryVersionCalls+fake.detailsCalls, raw)
	}
}

func TestVerify_ApiKeyIsCheckedLikeAReferenceToken(t *testing.T) {
	_, fake := validSetup(t)
	fake.status = http.StatusUnauthorized
	cmd := newTestCommand("AKCp8"+strings.Repeat("x", 68), fake)
	assert.ErrorContains(t, cmd.Run(), "reference token revoked")
	assert.Equal(t, 1, fake.detailsCalls)
}

func TestVerify_RefreshableProfile_NeverRefreshes(t *testing.T) {
	t.Setenv(coreutils.HomeDir, t.TempDir())
	certB64, key := generateTestCert(t)
	var serverCalls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/access/api/v1/cert/root":
			_, _ = w.Write([]byte(certB64))
		case "/artifactory/api/system/version":
			serverCalls = append(serverCalls, r.URL.Path+" "+r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"version":"7.179.0"}`))
		case "/access/api/v1/tokens/me":
			serverCalls = append(serverCalls, r.URL.Path+" "+r.Header.Get("Authorization"))
			_, _ = w.Write([]byte(`{"token_id":"id-1","subject":"jfac@01h/users/alice","scope":"applied-permissions/user"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer server.Close()

	now := time.Now()
	nearExpiry := func(lifetime, left time.Duration) string {
		claims := validClaims(now)
		claims["iat"] = now.Add(left - lifetime).Unix()
		claims["exp"] = now.Add(left).Unix()
		return signToken(t, key, validHeader(), claims)
	}
	noExpiry := validClaims(now)
	delete(noExpiry, "exp")
	profileToken := nearExpiry(10*time.Minute, 5*time.Minute)
	require.NoError(t, config.SaveServersConf([]*config.ServerDetails{{
		ServerId:     "login",
		Url:          server.URL + "/",
		AccessToken:  profileToken,
		RefreshToken: "refresh",
		WebLogin:     true,
		IsDefault:    true,
	}}))

	for name, token := range map[string]string{
		"10m lifetime, 5m left": nearExpiry(10*time.Minute, 5*time.Minute),
		"1h lifetime, 20m left": nearExpiry(time.Hour, 20*time.Minute),
		"no exp":                signToken(t, key, validHeader(), noExpiry),
		"profile's own token":   profileToken,
		"reference token":       "opaqueReferenceValue",
	} {
		t.Run(name, func(t *testing.T) {
			serverCalls = nil
			profile, err := config.GetSpecificConfig("login", true, true)
			require.NoError(t, err)

			start := time.Now()
			require.NoError(t, NewAccessTokenVerifyCommand().SetServerDetails(profile).SetToken(token).Run())
			assert.Less(t, time.Since(start), 5*time.Second)
			wantPath := "/artifactory/api/system/version"
			if !strings.Contains(token, ".") {
				wantPath = "/access/api/v1/tokens/me"
			}
			assert.Equal(t, []string{wantPath + " Bearer " + token}, serverCalls)

			saved, err := config.GetSpecificConfig("login", true, false)
			require.NoError(t, err)
			assert.Equal(t, profileToken, saved.AccessToken)
			assert.Equal(t, "refresh", saved.RefreshToken)
		})
	}
}

func TestTokenUnderInvestigationDetails_KeepsOnlyUrlAndClientCert(t *testing.T) {
	profile := &config.ServerDetails{
		ServerId:                "p",
		Url:                     "https://jpd.example/",
		User:                    "u",
		Password:                "p",
		AccessToken:             "profile-token",
		RefreshToken:            "r",
		ArtifactoryRefreshToken: "ar",
		SshKeyPath:              "k",
		SshPassphrase:           "s",
		ClientCertPath:          "c",
		ClientCertKeyPath:       "ck",
		InsecureTls:             true,
		WebLogin:                true,
	}
	assert.Equal(t, &config.ServerDetails{
		Url:                 "https://jpd.example/",
		ClientCertPath:      "c",
		ClientCertKeyPath:   "ck",
		AccessToken:         "token",
		DisableTokenRefresh: true,
	}, tokenUnderInvestigationDetails(profile, "token"))
}

func TestInsecureConnectionWarning(t *testing.T) {
	assert.Empty(t, insecureConnectionWarning(&config.ServerDetails{Url: "https://x/"}))
	warning := insecureConnectionWarning(&config.ServerDetails{Url: "http://x/"})
	assert.Contains(t, warning, "http://")
	assert.Contains(t, warning, "unencrypted")
}

func TestVerify_ServerDetailsHasNoRefreshTokens(t *testing.T) {
	key, fake := validSetup(t)
	cmd := newTestCommand(signToken(t, key, validHeader(), validClaims(testNow)), fake)
	profile := &config.ServerDetails{
		ServerId:                "p",
		Url:                     "https://jpd.example/",
		ArtifactoryUrl:          "https://jpd.example/artifactory/",
		AccessToken:             "profile-token",
		RefreshToken:            "r",
		ArtifactoryRefreshToken: "ar",
	}
	cmd.SetServerDetails(profile)
	require.NoError(t, cmd.Run())

	details, err := cmd.ServerDetails()
	require.NoError(t, err)
	again, err := cmd.ServerDetails()
	require.NoError(t, err)
	assert.Same(t, details, again)
	assert.Equal(t, &config.ServerDetails{
		ServerId:            "p",
		Url:                 "https://jpd.example/",
		ArtifactoryUrl:      "https://jpd.example/artifactory/",
		AccessToken:         "profile-token",
		DisableTokenRefresh: true,
	}, details)
	assert.Equal(t, "r", profile.RefreshToken)
	assert.Equal(t, "ar", profile.ArtifactoryRefreshToken)
}
