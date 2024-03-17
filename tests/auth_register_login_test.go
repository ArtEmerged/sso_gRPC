package tests

import (
	"sso/tests/suite"
	"testing"
	"time"

	ssov1 "github.com/ArtEmerged/protos_sso/gen/go/sso"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	emptyAppID = 0
	appID      = 1
	appSecret  = "test-secret"

	passDefaultLen = 10
)

func TestRegisterLoginHappyPath(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	respReg, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{Email: email, Password: password})

	require.NoError(t, err)
	assert.NotEmpty(t, respReg.UserId)

	respLogin, err := st.AuthClient.Login(ctx, &ssov1.LoginRequest{Email: email, Password: password, AppId: appID})

	loginTime := time.Now()

	require.NoError(t, err)

	token := respLogin.Token
	require.NotEmpty(t, token)

	tokenParse, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(appSecret), nil
	})

	require.NoError(t, err)

	claims, ok := tokenParse.Claims.(jwt.MapClaims)

	assert.True(t, ok)

	assert.Equal(t, respReg.GetUserId(), int64(claims["uid"].(float64)))
	assert.Equal(t, email, claims["email"].(string))
	assert.Equal(t, appID, int(claims["app_id"].(float64)))

	const deltaSeconds = 1

	assert.InDelta(t, loginTime.Add(st.Cfg.TokenTTL).Unix(), claims["exp"].(float64), deltaSeconds)
}

func TestRegisterLoginDuplicatedRegistration(t *testing.T) {
	ctx, st := suite.New(t)

	email := gofakeit.Email()
	password := randomFakePassword()

	resp, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{Email: email, Password: password})
	require.NoError(t, err)

	require.NotEmpty(t, resp.GetUserId())

	resp, err = st.AuthClient.Register(ctx, &ssov1.RegisterRequest{Email: email, Password: password})

	require.Error(t, err)
	assert.Empty(t, resp.GetUserId())
	assert.ErrorContains(t, err, "user already exists")
}

func TestRegisterFailCase(t *testing.T) {
	ctx, st := suite.New(t)
	tests := []struct {
		name     string
		email    string
		password string
		wantErr  string
	}{
		{
			name:     "Register with Empty Password",
			email:    gofakeit.Email(),
			password: "",
			wantErr:  "password is required",
		},
		{
			name:     "Register with Empty Email",
			email:    "",
			password: randomFakePassword(),
			wantErr:  "email is required",
		},
		{
			name:     "Register with Empty Password And Password",
			email:    "",
			password: "",
			wantErr:  "email is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := st.AuthClient.Register(ctx, &ssov1.RegisterRequest{Email: test.email, Password: test.password})
			require.Error(t, err)
			require.Contains(t, err.Error(), test.wantErr)
		})
	}
}

func randomFakePassword() string {
	return gofakeit.Password(true, true, true, true, false, passDefaultLen)
}
