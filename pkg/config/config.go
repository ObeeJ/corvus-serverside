package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	Scanner ScannerConfig `mapstructure:"scanner"`
	Store   StoreConfig   `mapstructure:"store"`
	Log     LogConfig     `mapstructure:"log"`
	Watch   WatchConfig   `mapstructure:"watch"`
}

type ScannerConfig struct {
	Timeout      time.Duration `mapstructure:"timeout"`
	Concurrency  int           `mapstructure:"concurrency"`
	DefaultPorts string        `mapstructure:"default_ports"`
	Rate         int           `mapstructure:"rate"`
}

type StoreConfig struct {
	Path      string        `mapstructure:"path"`
	Retention time.Duration `mapstructure:"retention"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type WatchConfig struct {
	DefaultInterval time.Duration `mapstructure:"default_interval"`
}

func Load(cfgFile string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("default")
		v.AddConfigPath("./configs")
		v.AddConfigPath("$HOME/.corvus")
		v.AddConfigPath("/etc/corvus")
	}

	v.SetEnvPrefix("CORVUS")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.SetDefault("scanner.timeout", "3s")
	v.SetDefault("scanner.concurrency", 500)
	v.SetDefault("scanner.default_ports", "1-1024,8080,8443,9200,5432,3306,6379,27017")
	v.SetDefault("scanner.rate", 0)
	v.SetDefault("store.path", "/var/lib/corvus/corvus.db")
	v.SetDefault("store.retention", "2160h") // 90d
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "text")
	v.SetDefault("watch.default_interval", "5m")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	decodeHook := mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	)
	if err := v.Unmarshal(&cfg, viper.DecodeHook(decodeHook)); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}
