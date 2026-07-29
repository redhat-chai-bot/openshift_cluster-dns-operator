package controller

import (
	"crypto/tls"
	"fmt"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/crypto"
	"github.com/sirupsen/logrus"
)

// TODO: replace with library-go CurveIDsForTLSGroups once openshift/library-go#2347 merges.
var tlsGroupToCurveID = map[configv1.TLSGroup]tls.CurveID{
	configv1.TLSGroupX25519:         tls.X25519,
	configv1.TLSGroupSecP256r1:      tls.CurveP256,
	configv1.TLSGroupSecP384r1:      tls.CurveP384,
	configv1.TLSGroupSecP521r1:      tls.CurveP521,
	configv1.TLSGroupX25519MLKEM768: tls.X25519MLKEM768,
}

// TLSGroupToCurveID converts a configv1.TLSGroup name to its crypto/tls
// CurveID. The second return value is false when the group is not supported
// by the Go runtime.
func TLSGroupToCurveID(group configv1.TLSGroup) (tls.CurveID, bool) {
	id, ok := tlsGroupToCurveID[group]
	return id, ok
}

// TLSConfigFromProfile builds a *tls.Config from the given TLSProfileSpec.
// Cipher names in the spec use OpenSSL naming. Groups that cannot be mapped
// to a Go CurveID are logged and skipped.
func TLSConfigFromProfile(spec *configv1.TLSProfileSpec) (*tls.Config, error) {
	if spec == nil {
		return crypto.SecureTLSConfig(&tls.Config{}), nil
	}

	cfg := &tls.Config{}

	if len(spec.Ciphers) > 0 {
		ianaNames := crypto.OpenSSLToIANACipherSuites(spec.Ciphers)
		var suites []uint16
		for _, name := range ianaNames {
			id, err := crypto.CipherSuite(name)
			if err != nil {
				logrus.Warningf("TLSConfigFromProfile: unsupported cipher suite %q, skipping", name)
				continue
			}
			suites = append(suites, id)
		}
		cfg.CipherSuites = suites
	}

	if len(spec.MinTLSVersion) > 0 {
		v, err := crypto.TLSVersion(string(spec.MinTLSVersion))
		if err != nil {
			return nil, fmt.Errorf("invalid TLS version %q: %w", spec.MinTLSVersion, err)
		}
		cfg.MinVersion = v
	}

	if len(spec.Groups) > 0 {
		var curves []tls.CurveID
		for _, g := range spec.Groups {
			if id, ok := TLSGroupToCurveID(g); ok {
				curves = append(curves, id)
			} else {
				logrus.Warningf("TLSConfigFromProfile: unsupported TLS group %q (Go runtime may not support it yet), skipping", g)
			}
		}
		if len(curves) > 0 {
			cfg.CurvePreferences = curves
		}
	}

	return crypto.SecureTLSConfig(cfg), nil
}

// MetricsTLSOptsFromAPIServer returns TLS configuration mutators for the
// operator metrics server, gated on the cluster's tlsAdherence policy.
// When ShouldHonorClusterTLSProfile returns false (Legacy/NoOpinion), no
// mutators are returned and the caller should use default TLS settings.
func MetricsTLSOptsFromAPIServer(apiServer *configv1.APIServer) ([]func(*tls.Config), error) {
	if apiServer == nil {
		return nil, nil
	}

	adherence := apiServer.Spec.TLSAdherence

	switch adherence {
	case configv1.TLSAdherencePolicyNoOpinion,
		configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
		configv1.TLSAdherencePolicyStrictAllComponents:
	default:
		logrus.Warningf("MetricsTLSOptsFromAPIServer: unrecognized tlsAdherence value %q, defaulting to Strict behavior (honoring cluster TLS profile)", adherence)
	}

	if !crypto.ShouldHonorClusterTLSProfile(adherence) {
		logrus.Infof("MetricsTLSOptsFromAPIServer: tlsAdherence=%q, not applying cluster TLS profile to operator metrics", adherence)
		return nil, nil
	}

	logrus.Infof("MetricsTLSOptsFromAPIServer: tlsAdherence=%q, applying cluster TLS security profile to operator metrics", adherence)

	profileSpec := TLSProfileSpecForSecurityProfile(apiServer.Spec.TLSSecurityProfile)
	tlsCfg, err := TLSConfigFromProfile(profileSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to build TLS config from cluster profile: %w", err)
	}

	mutator := func(cfg *tls.Config) {
		cfg.CipherSuites = tlsCfg.CipherSuites
		cfg.MinVersion = tlsCfg.MinVersion
		if len(tlsCfg.CurvePreferences) > 0 {
			cfg.CurvePreferences = tlsCfg.CurvePreferences
		}
	}
	return []func(*tls.Config){mutator}, nil
}

// TLSProfileSpecForSecurityProfile returns a TLSProfileSpec based on the
// provided security profile, or the Intermediate profile if an unknown
// profile type is provided or the profile is nil.
func TLSProfileSpecForSecurityProfile(profile *configv1.TLSSecurityProfile) *configv1.TLSProfileSpec {
	if profile != nil {
		switch profile.Type {
		case configv1.TLSProfileOldType, configv1.TLSProfileModernType:
			return configv1.TLSProfiles[profile.Type]
		case configv1.TLSProfileIntermediateType:
			return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		case configv1.TLSProfileCustomType:
			if profile.Custom != nil {
				return &profile.Custom.TLSProfileSpec
			}
			logrus.Warningf("TLSProfileSpecForSecurityProfile: custom TLS profile has nil spec, using Intermediate default")
		}
	}
	return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
}
