package tokenprovider

import (
	"context"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
)

type jwtSource struct {
	cacheKey string
	conf     jwt.Config
}

type jwtIdentitySource struct {
	cacheKey string
	conf     jwt.Config
}

// NewJwtAccessTokenProvider returns a token provider for jwt file authentication
func NewJwtAccessTokenProvider(cfg Config) TokenProvider {
	return &tokenProviderImpl{
		&jwtSource{
			cacheKey: createCacheKey("jwt", &cfg),
			conf: jwt.Config{
				Email:      cfg.JwtTokenConfig.Email,
				PrivateKey: cfg.JwtTokenConfig.PrivateKey,
				TokenURL:   cfg.JwtTokenConfig.URI,
				Scopes:     cfg.Scopes,
			},
		},
	}
}

func (source *jwtSource) getCacheKey() string {
	return source.cacheKey
}

func (source *jwtSource) getToken(ctx context.Context) (*oauth2.Token, error) {
	return getTokenSource(ctx, &source.conf).Token()
}

// getTokenSource returns a TokenSource.
// Stubbable by tests.
var getTokenSource = func(ctx context.Context, conf *jwt.Config) oauth2.TokenSource {
	return conf.TokenSource(ctx)
}

// NewJwtIdentityTokenProvider returns a token provider for JWT file authentication that provides Google Identity Tokens
func NewJwtIdentityTokenProvider(cfg Config) TokenProvider {

	privateClaims := map[string]interface{}{
		"target_audience": cfg.JwtTokenConfig.TargetAudience,
	}

	return &tokenProviderImpl{
		&jwtIdentitySource{
			cacheKey: createCacheKey("jwt_identity", &cfg),
			conf: jwt.Config{
				Email:         cfg.JwtTokenConfig.Email,
				PrivateKey:    cfg.JwtTokenConfig.PrivateKey,
				TokenURL:      cfg.JwtTokenConfig.URI,
				Scopes:        cfg.Scopes,
				Subject:       cfg.JwtTokenConfig.Email,
				Expires:       time.Hour,
				PrivateClaims: privateClaims,
				UseIDToken:    true,
			},
		},
	}
}

func (source *jwtIdentitySource) getCacheKey() string {
	return source.cacheKey
}

func (source *jwtIdentitySource) getToken(ctx context.Context) (*oauth2.Token, error) {
	return getTokenSource(ctx, &source.conf).Token()
}
