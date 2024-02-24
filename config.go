package jwtplugin

// Config содержит конфигурационные параметры для плагина.
type Config struct {
	Secret string `mapstructure:"secret"`
}
