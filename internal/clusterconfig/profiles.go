package clusterconfig

import (
	"encoding/hex"
	"rauth/internal/clustertransport"
)

// NodeProfile contains only the reviewed non-secret security fingerprint and
// whether a complete GeoIP database is required for this node's policy.
type NodeProfile struct {
	SecurityFingerprint string `json:"security_fingerprint"`
	RequireGeoIP        bool   `json:"require_geoip"`
}
type Profiles struct {
	Schema int                    `json:"schema"`
	Nodes  map[string]NodeProfile `json:"nodes"`
}

func ParseProfiles(raw []byte, clusterID, self string) (Profiles, error) {
	var profiles Profiles
	if len(raw) == 0 || len(raw) > 64<<10 || strictJSON(raw, &profiles) != nil || profiles.Schema != 1 || len(profiles.Nodes) < 1 || len(profiles.Nodes) > 64 {
		return Profiles{}, ErrInvalid
	}
	for id, profile := range profiles.Nodes {
		if _, err := clustertransport.NodeURI(clusterID, id); err != nil {
			return Profiles{}, ErrInvalid
		}
		fingerprint, err := hex.DecodeString(profile.SecurityFingerprint)
		if err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != profile.SecurityFingerprint {
			return Profiles{}, ErrInvalid
		}
	}
	if _, ok := profiles.Nodes[self]; !ok {
		return Profiles{}, ErrInvalid
	}
	return profiles, nil
}
