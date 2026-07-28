package controller

import (
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
)

func TestTLSGroupToCurveID(t *testing.T) {
	tests := []struct {
		group  configv1.TLSGroup
		wantID tls.CurveID
		wantOK bool
	}{
		{configv1.TLSGroupX25519, tls.X25519, true},
		{configv1.TLSGroupSecP256r1, tls.CurveP256, true},
		{configv1.TLSGroupSecP384r1, tls.CurveP384, true},
		{configv1.TLSGroupSecP521r1, tls.CurveP521, true},
		{configv1.TLSGroupX25519MLKEM768, tls.X25519MLKEM768, true},
		{"UnknownGroup", 0, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.group), func(t *testing.T) {
			id, ok := TLSGroupToCurveID(tt.group)
			if ok != tt.wantOK {
				t.Fatalf("TLSGroupToCurveID(%q): got ok=%v, want %v", tt.group, ok, tt.wantOK)
			}
			if id != tt.wantID {
				t.Errorf("TLSGroupToCurveID(%q): got id=%v, want %v", tt.group, id, tt.wantID)
			}
		})
	}
}

func TestTLSConfigFromProfile(t *testing.T) {
	t.Run("nil spec returns secure defaults", func(t *testing.T) {
		cfg, err := TLSConfigFromProfile(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
	})

	t.Run("intermediate profile", func(t *testing.T) {
		spec := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		cfg, err := TLSConfigFromProfile(spec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS12)
		}
		if len(cfg.CipherSuites) == 0 {
			t.Error("expected non-empty CipherSuites")
		}
	})

	t.Run("custom profile with groups", func(t *testing.T) {
		spec := &configv1.TLSProfileSpec{
			Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			MinTLSVersion: configv1.VersionTLS12,
			Groups: []configv1.TLSGroup{
				configv1.TLSGroupX25519,
				configv1.TLSGroupSecP256r1,
			},
		}
		cfg, err := TLSConfigFromProfile(spec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.CurvePreferences) != 2 {
			t.Errorf("CurvePreferences: got %d entries, want 2", len(cfg.CurvePreferences))
		}
	})

	t.Run("unsupported groups are skipped", func(t *testing.T) {
		spec := &configv1.TLSProfileSpec{
			Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			MinTLSVersion: configv1.VersionTLS12,
			Groups:        []configv1.TLSGroup{"UnknownGroup"},
		}
		cfg, err := TLSConfigFromProfile(spec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.CurvePreferences) != 0 {
			t.Errorf("CurvePreferences: got %d entries, want 0", len(cfg.CurvePreferences))
		}
	})

	t.Run("mix of supported and unsupported groups", func(t *testing.T) {
		spec := &configv1.TLSProfileSpec{
			Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			MinTLSVersion: configv1.VersionTLS12,
			Groups: []configv1.TLSGroup{
				configv1.TLSGroupX25519,
				configv1.TLSGroupSecP256r1MLKEM768,
				configv1.TLSGroupSecP384r1MLKEM1024,
			},
		}
		cfg, err := TLSConfigFromProfile(spec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// SecP256r1MLKEM768 and SecP384r1MLKEM1024 require Go 1.26+;
		// only X25519 should be mapped on the current Go version.
		if len(cfg.CurvePreferences) != 1 {
			t.Errorf("CurvePreferences: got %d entries, want 1", len(cfg.CurvePreferences))
		}
		if cfg.CurvePreferences[0] != tls.X25519 {
			t.Errorf("CurvePreferences[0]: got %v, want X25519", cfg.CurvePreferences[0])
		}
	})

	t.Run("invalid TLS version returns error", func(t *testing.T) {
		spec := &configv1.TLSProfileSpec{
			MinTLSVersion: "InvalidVersion",
		}
		_, err := TLSConfigFromProfile(spec)
		if err == nil {
			t.Fatal("expected error for invalid TLS version")
		}
	})

	t.Run("empty groups leaves CurvePreferences nil", func(t *testing.T) {
		spec := &configv1.TLSProfileSpec{
			Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
			MinTLSVersion: configv1.VersionTLS12,
		}
		cfg, err := TLSConfigFromProfile(spec)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CurvePreferences != nil {
			t.Errorf("expected nil CurvePreferences, got %v", cfg.CurvePreferences)
		}
	})
}

func TestMetricsTLSOptsFromAPIServer(t *testing.T) {
	tests := []struct {
		name            string
		apiServer       *configv1.APIServer
		wantNil         bool
		wantErr         bool
		expectedProfile *configv1.TLSProfileSpec
	}{
		{
			name:      "nil APIServer returns nil",
			apiServer: nil,
			wantNil:   true,
		},
		{
			name: "NoOpinion (empty string) returns nil",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyNoOpinion,
				},
			},
			wantNil: true,
		},
		{
			name: "LegacyAdheringComponentsOnly returns nil",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
				},
			},
			wantNil: true,
		},
		{
			name: "StrictAllComponents returns TLS mutators",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			},
			wantNil: false,
		},
		{
			name: "unknown value returns TLS mutators (defaults to Strict)",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: "FuturePolicy",
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
				},
			},
			wantNil:         false,
			expectedProfile: configv1.TLSProfiles[configv1.TLSProfileOldType],
		},
		{
			name: "StrictAllComponents with nil TLSSecurityProfile uses Intermediate defaults",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence:       configv1.TLSAdherencePolicyStrictAllComponents,
					TLSSecurityProfile: nil,
				},
			},
			wantNil:         false,
			expectedProfile: configv1.TLSProfiles[configv1.TLSProfileIntermediateType],
		},
		{
			name: "StrictAllComponents with explicit profile applies it",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
				},
			},
			wantNil:         false,
			expectedProfile: configv1.TLSProfiles[configv1.TLSProfileOldType],
		},
		{
			name: "StrictAllComponents with Custom profile including Groups",
			apiServer: &configv1.APIServer{
				Spec: configv1.APIServerSpec{
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{
							TLSProfileSpec: configv1.TLSProfileSpec{
								Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
								MinTLSVersion: configv1.VersionTLS12,
								Groups: []configv1.TLSGroup{
									configv1.TLSGroupX25519,
									configv1.TLSGroupSecP256r1,
								},
							},
						},
					},
				},
			},
			wantNil: false,
			expectedProfile: &configv1.TLSProfileSpec{
				Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
				MinTLSVersion: configv1.VersionTLS12,
				Groups: []configv1.TLSGroup{
					configv1.TLSGroupX25519,
					configv1.TLSGroupSecP256r1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := MetricsTLSOptsFromAPIServer(tt.apiServer)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MetricsTLSOptsFromAPIServer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantNil && opts != nil {
				t.Errorf("expected nil opts, got %v", opts)
			}
			if !tt.wantNil && opts == nil {
				t.Error("expected non-nil opts, got nil")
			}
			if !tt.wantNil && opts != nil {
				cfg := &tls.Config{}
				opts[0](cfg)
				if cfg.MinVersion == 0 {
					t.Error("expected MinVersion to be set by mutator")
				}
				if tt.expectedProfile != nil {
					expectedCfg, err := TLSConfigFromProfile(tt.expectedProfile)
					if err != nil {
						t.Fatalf("failed to build expected config: %v", err)
					}
					if cfg.MinVersion != expectedCfg.MinVersion {
						t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, expectedCfg.MinVersion)
					}
					if len(cfg.CipherSuites) != len(expectedCfg.CipherSuites) {
						t.Errorf("CipherSuites count: got %d, want %d", len(cfg.CipherSuites), len(expectedCfg.CipherSuites))
					} else {
						for i := range expectedCfg.CipherSuites {
							if cfg.CipherSuites[i] != expectedCfg.CipherSuites[i] {
								t.Errorf("CipherSuites[%d]: got %d, want %d", i, cfg.CipherSuites[i], expectedCfg.CipherSuites[i])
							}
						}
					}
					if len(cfg.CurvePreferences) != len(expectedCfg.CurvePreferences) {
						t.Errorf("CurvePreferences count: got %d, want %d", len(cfg.CurvePreferences), len(expectedCfg.CurvePreferences))
					} else {
						for i := range expectedCfg.CurvePreferences {
							if cfg.CurvePreferences[i] != expectedCfg.CurvePreferences[i] {
								t.Errorf("CurvePreferences[%d]: got %v, want %v", i, cfg.CurvePreferences[i], expectedCfg.CurvePreferences[i])
							}
						}
					}
				}
			}
		})
	}
}

func TestTLSProfileSpecForSecurityProfile(t *testing.T) {
	t.Run("nil profile defaults to Intermediate", func(t *testing.T) {
		spec := TLSProfileSpecForSecurityProfile(nil)
		intermediate := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		if spec.MinTLSVersion != intermediate.MinTLSVersion {
			t.Errorf("MinTLSVersion: got %s, want %s", spec.MinTLSVersion, intermediate.MinTLSVersion)
		}
	})

	t.Run("custom profile with nil Custom defaults to Intermediate", func(t *testing.T) {
		profile := &configv1.TLSSecurityProfile{
			Type:   configv1.TLSProfileCustomType,
			Custom: nil,
		}
		spec := TLSProfileSpecForSecurityProfile(profile)
		intermediate := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
		if spec.MinTLSVersion != intermediate.MinTLSVersion {
			t.Errorf("MinTLSVersion: got %s, want %s", spec.MinTLSVersion, intermediate.MinTLSVersion)
		}
	})

	t.Run("custom profile preserves groups", func(t *testing.T) {
		profile := &configv1.TLSSecurityProfile{
			Type: configv1.TLSProfileCustomType,
			Custom: &configv1.CustomTLSProfile{
				TLSProfileSpec: configv1.TLSProfileSpec{
					Ciphers:       []string{"ECDHE-RSA-AES256-GCM-SHA384"},
					MinTLSVersion: configv1.VersionTLS12,
					Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519},
				},
			},
		}
		spec := TLSProfileSpecForSecurityProfile(profile)
		if len(spec.Groups) != 1 || spec.Groups[0] != configv1.TLSGroupX25519 {
			t.Errorf("Groups: got %v, want [X25519]", spec.Groups)
		}
	})

	t.Run("old profile", func(t *testing.T) {
		profile := &configv1.TLSSecurityProfile{Type: configv1.TLSProfileOldType}
		spec := TLSProfileSpecForSecurityProfile(profile)
		old := configv1.TLSProfiles[configv1.TLSProfileOldType]
		if spec.MinTLSVersion != old.MinTLSVersion {
			t.Errorf("MinTLSVersion: got %s, want %s", spec.MinTLSVersion, old.MinTLSVersion)
		}
	})

	t.Run("modern profile", func(t *testing.T) {
		profile := &configv1.TLSSecurityProfile{Type: configv1.TLSProfileModernType}
		spec := TLSProfileSpecForSecurityProfile(profile)
		modern := configv1.TLSProfiles[configv1.TLSProfileModernType]
		if spec.MinTLSVersion != modern.MinTLSVersion {
			t.Errorf("MinTLSVersion: got %s, want %s", spec.MinTLSVersion, modern.MinTLSVersion)
		}
	})
}
