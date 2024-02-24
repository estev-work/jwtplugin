package jwt

// Config содержит конфигурационные параметры для плагина.
type Config struct {
	Secret string `mapstructure:"secret"`
}

func (cfg *Config) InitDefaults() {
	if cfg.Secret == "" {
		cfg.Secret = "secret"
	}
}
