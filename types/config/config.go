package config

type Config struct {
	Settings struct {
		LogLevel               string `yaml:"logLevel"`
		KeepDroplets           bool   `yaml:"KeepDroplets"`
		KeepScanLogs           bool   `yaml:"KeepScanLogs"`
		KeepOCI                bool   `yaml:"KeepOCI"`
		ExecutionThreads       int    `yaml:"execution_threads"`
		AlwaysDownloadVulndb   bool   `yaml:"always_download_vulndb"`
		Standalone             bool   `yaml:"standalone"`
		StandaloneSeverity     string `yaml:"standalone_severity"`
		StandaloneHasFix       bool   `yaml:"standalone_hasfix"`
		StandaloneDaysSinceFix int    `yaml:"standalone_days_since_fix"`
	} `yaml:"settings"`
	Config struct {
		CFAuthEndpoint    string `yaml:"cf_auth_endpoint"`
		CFAPIEndpoint     string `yaml:"cf_api_endpoint"`
		SysdigPolicy      string `yaml:"sysdig_policy"`
		ServiceInstance   string `yaml:"service_instance"`
		SysdigCliCommand  string `yaml:"sysdig_cli_command"`
		SysdigAPIToken    string `yaml:"sysdig_api_token"`
		SysdigAPIEndpoint string `yaml:"sysdig_api_endpoint"`
		CFUsername        string `yaml:"cf_username"`
		CFPassword        string `yaml:"cf_password"`
	} `yaml:"config"`
	Stacks map[string]string `yaml:"stacks"`
}
