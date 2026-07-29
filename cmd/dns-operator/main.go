package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"time"

	configclient "github.com/openshift/client-go/config/clientset/versioned"
	operatorcontroller "github.com/openshift/cluster-dns-operator/pkg/operator/controller"

	"github.com/openshift/cluster-dns-operator/pkg/operator"
	operatorconfig "github.com/openshift/cluster-dns-operator/pkg/operator/config"
	statuscontroller "github.com/openshift/cluster-dns-operator/pkg/operator/controller/status"

	"github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

const operatorNamespace = "openshift-dns-operator"

func main() {
	metricsBindAddr := flag.String("metrics-bind-addr", "127.0.0.1:60000", "The TCP address for the metrics endpoint.")
	metricsCertDir := flag.String("metrics-cert-dir", "", "The directory containing tls.crt and tls.key for the metrics endpoint.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Collect operator configuration.
	releaseVersion := os.Getenv("RELEASE_VERSION")
	if len(releaseVersion) == 0 {
		releaseVersion = statuscontroller.UnknownVersionValue
		logrus.Infof("RELEASE_VERSION environment variable is missing, defaulting to %q", statuscontroller.UnknownVersionValue)
	}
	coreDNSImage := os.Getenv("IMAGE")
	if len(coreDNSImage) == 0 {
		logrus.Fatalf("IMAGE environment variable is required")
	}
	cliImage := os.Getenv("OPENSHIFT_CLI_IMAGE")
	if len(cliImage) == 0 {
		logrus.Fatalf("OPENSHIFT_CLI_IMAGE environment variable is required")
	}

	kubeRBACProxyImage := os.Getenv("KUBE_RBAC_PROXY_IMAGE")
	if len(kubeRBACProxyImage) == 0 {
		logrus.Fatalf("KUBE_RBAC_PROXY_IMAGE environment variable is required")
	}

	kubeConfig, err := config.GetConfig()
	if err != nil {
		logrus.Fatalf("failed to get kube config: %v", err)
	}

	// Build TLS options for the operator metrics server, gated on the
	// cluster's tlsAdherence policy.  Under LegacyAdheringComponentsOnly
	// (the default) no cluster TLS profile is applied because operator
	// metrics is a newly adhering surface.  Under StrictAllComponents the
	// cluster TLS profile is applied.
	// NOTE: the TLS profile is read once at startup; runtime changes to
	// APIServer require an operator restart.
	var metricsTLSOpts []func(*tls.Config)
	if *metricsCertDir != "" {
		cfgClient, err := configclient.NewForConfig(kubeConfig)
		if err != nil {
			logrus.Fatalf("failed to create config client: %v", err)
		}
		// Retry fetching the APIServer config with exponential backoff
		// (2s, 4s, 8s) because the API server may be temporarily
		// unreachable during cluster bootstrap or upgrades.
		backoff := wait.Backoff{
			Duration: 2 * time.Second,
			Factor:   2,
			Steps:    3,
		}
		var lastErr error
		err = wait.ExponentialBackoff(backoff, func() (bool, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			apiServer, getErr := cfgClient.ConfigV1().APIServers().Get(ctx, "cluster", metav1.GetOptions{})
			if getErr != nil {
				logrus.Warningf("failed to get apiserver config (will retry): %v", getErr)
				lastErr = getErr
				return false, nil
			}
			metricsTLSOpts, lastErr = operatorcontroller.MetricsTLSOptsFromAPIServer(apiServer)
			if lastErr != nil {
				return false, lastErr
			}
			return true, nil
		})
		// If all retries were exhausted, fall back to the Intermediate
		// TLS profile so the operator can still start with secure defaults.
		// A non-transient error from MetricsTLSOptsFromAPIServer is fatal.
		if err != nil {
			if wait.Interrupted(err) {
				logrus.Warningf("failed to get apiserver config after retries, falling back to Intermediate TLS profile for operator metrics: %v", lastErr)
			} else {
				logrus.Fatalf("failed to build TLS options from apiserver config: %v", err)
			}
			profileSpec := operatorcontroller.TLSProfileSpecForSecurityProfile(nil)
			tlsCfg, tlsErr := operatorcontroller.TLSConfigFromProfile(profileSpec)
			if tlsErr != nil {
				logrus.Fatalf("failed to build TLS config from Intermediate profile: %v", tlsErr)
			}
			metricsTLSOpts = append(metricsTLSOpts, func(cfg *tls.Config) {
				cfg.CipherSuites = tlsCfg.CipherSuites
				cfg.MinVersion = tlsCfg.MinVersion
				if len(tlsCfg.CurvePreferences) > 0 {
					cfg.CurvePreferences = tlsCfg.CurvePreferences
				}
			})
		}
	}

	operatorConfig := operatorconfig.Config{
		OperatorNamespace:      operatorNamespace,
		OperatorReleaseVersion: releaseVersion,
		CoreDNSImage:           coreDNSImage,
		OpenshiftCLIImage:      cliImage,
		KubeRBACProxyImage:     kubeRBACProxyImage,
		MetricsBindAddress:     *metricsBindAddr,
		MetricsCertDir:         *metricsCertDir,
		MetricsTLSOpts:         metricsTLSOpts,
	}

	ctx := signals.SetupSignalHandler()
	// Set up and start the operator.
	op, err := operator.New(ctx, operatorConfig, kubeConfig)
	if err != nil {
		logrus.Fatalf("failed to create operator: %v", err)
	}
	if err := op.Start(ctx); err != nil {
		logrus.Fatalf("failed to start operator: %v", err)
	}
}
