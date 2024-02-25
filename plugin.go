package jwt

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/roadrunner-server/errors"
	"github.com/roadrunner-server/logger/v4"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

const (
	PluginName string = "jwt"
)

type Plugin struct {
	cfg    *Config
	logger logger.Logger
}

type Configurator interface {
	UnmarshalKey(name string, out any) error
	Has(name string) bool
}

type Logger interface {
	NamedLogger(name string) *zap.Logger
}

func (plugin *Plugin) Init(cfg Configurator, log Logger) error {
	const op = errors.Op("jwt_plugin_init")
	if !cfg.Has(PluginName) {
		return errors.E(op, errors.Disabled)
	}

	err := cfg.UnmarshalKey(PluginName, &plugin.cfg)
	if err != nil {
		return errors.E(op, err)
	}

	plugin.cfg.InitDefaults()
	plugin.logger = log
	plugin.logger.NamedLogger(PluginName).Debug("plugin was started")
	return nil
}

func (plugin *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			plugin.errorResponse(writer, "Unauthorized access", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(plugin.cfg.Secret), nil
		})
		if err != nil {
			plugin.logger.NamedLogger(PluginName).Debug("invalid JWT token")
			writer.WriteHeader(http.StatusUnauthorized)
			plugin.errorResponse(writer, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(writer, r)
	})
}

func (plugin *Plugin) errorResponse(writer http.ResponseWriter, errorMessage string, status int) {
	writer.WriteHeader(status)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusUnauthorized)
	resp := map[string]string{"error": errorMessage}
	jsonResp, _ := json.MarshalIndent(resp, "", "  ")
	_, err := writer.Write(jsonResp)
	if err != nil {
		plugin.logger.NamedLogger(PluginName).Debug("Error write response json")
	}
}

func (plugin *Plugin) Name() string {
	return PluginName
}
