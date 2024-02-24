package jwtplugin

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/roadrunner-server/config/v4"
	"github.com/roadrunner-server/logger/v4"
	"net/http"
	"strings"
)

const (
	PluginName string = "jwtplugin"
)

type Plugin struct {
	cfg    *Config
	logger logger.Logger
}

func (p *Plugin) Init(cfg config.Plugin, logger logger.Logger) error {
	var appendConfig Config
	if err := cfg.UnmarshalKey("jwt_plugin", &appendConfig); err != nil {
		return err
	}

	p.cfg = &appendConfig
	p.logger = logger
	return nil
}

func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(p.cfg.Secret), nil
		})

		if err != nil {
			p.logger.NamedLogger("jwtplugin").Error("invalid JWT token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (p *Plugin) Name() string {
	return PluginName
}
