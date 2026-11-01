package core

import "rauth/internal/clusterconfig"

// LoadClusterBootstrap applies guarded private host material before any database
// access. Offline control tools use the same credentials and profile validation
// as the server. An absent opt-in preserves existing standalone configuration.
func LoadClusterBootstrap(cfg *Config) (*clusterconfig.Loaded, error) {
	if cfg == nil {
		return nil, clusterconfig.ErrInvalid
	}
	if cfg.ClusterConfigFile == "" {
		return nil, nil
	}
	material, err := clusterconfig.Load(cfg.ClusterConfigFile)
	if err != nil {
		return nil, err
	}
	spec := material.Config()
	if err = material.CheckCacheRoot(); err != nil {
		return nil, err
	}
	cfg.ServerSecret = material.CookieSecret()
	cfg.PostgresURL = material.DatabaseURL("auth")
	cfg.AuthStateKeyFile = spec.AuthStateKeyFile
	cfg.ListenAddr = spec.PublicListen
	if spec.Role == clusterconfig.Control {
		cfg.MaxMindDBPath = spec.GeoIPFile
	}
	if _, err = WorkerPolicyOptionsForConfig(spec.NodeID, cfg); err != nil {
		return nil, err
	}
	return material, nil
}
