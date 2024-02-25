package jwt

type Config struct {
	Secret string `mapstructure:"secret"`
}

func (config *Config) InitDefaults() {
	if config.Secret == "" {
		panic("JWT secret required!")
	}
}
