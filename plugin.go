package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/roadrunner-server/errors"
	"github.com/roadrunner-server/logger/v4"
	"go.uber.org/zap"
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

type Configurer interface {
	// UnmarshalKey takes a single key and unmarshal it into a Struct.
	UnmarshalKey(name string, out any) error
	// Has checks if config section exists.
	Has(name string) bool
}

type Logger interface {
	NamedLogger(name string) *zap.Logger
}

func (s *Plugin) Init(cfg Configurer) error {
	const op = errors.Op("jwt_plugin_init")
	if !cfg.Has(PluginName) {
		return errors.E(op, errors.Disabled)
	}

	err := cfg.UnmarshalKey(PluginName, &s.cfg)
	if err != nil {
		return errors.E(op, err)
	}

	s.cfg.InitDefaults()
	s.logger.NamedLogger("jwt_logger")
	return nil
}

func (s *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(s.cfg.Secret), nil
		})

		if err != nil {
			s.logger.NamedLogger("jwtplugin").Error("invalid JWT token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Plugin) Name() string {
	return PluginName
}
