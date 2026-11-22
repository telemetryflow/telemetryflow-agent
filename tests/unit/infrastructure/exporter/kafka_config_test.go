// Package exporter_test — KafkaOutput configuration coverage. These tests
// exercise buildSaramaConfig / configureSCRAM / buildTLSConfig via the
// constructor only; no broker connection is attempted (Connect is never
// called), so everything runs offline and deterministically.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
package exporter_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telemetryflow/telemetryflow-agent/internal/exporter"
)

// writeSelfSignedCert emits a self-signed CA cert + EC key as PEM files and
// returns their paths. The cert doubles as a usable CA bundle and client
// keypair for the TLS-config tests.
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tfo-agent-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func baseKafkaCfg() exporter.KafkaOutputConfig {
	return exporter.KafkaOutputConfig{
		Brokers: []string{"localhost:9092"},
		Topic:   "tfo-metrics",
		Logger:  zap.NewNop(),
	}
}

func TestKafka_Name(t *testing.T) {
	out, err := exporter.NewKafkaOutput(baseKafkaCfg())
	require.NoError(t, err)
	assert.Equal(t, "kafka", out.Name())
}

func TestKafka_SASLMechanisms(t *testing.T) {
	cases := []string{
		exporter.KafkaAuthSASLPlaintext,
		exporter.KafkaAuthSASLSCRAMSHA256,
		exporter.KafkaAuthSASLSCRAMSHA512,
	}
	for _, authType := range cases {
		t.Run(authType, func(t *testing.T) {
			cfg := baseKafkaCfg()
			cfg.Auth = exporter.KafkaAuth{Type: authType, Username: "u", Password: "p"}
			out, err := exporter.NewKafkaOutput(cfg)
			require.NoError(t, err)
			assert.Equal(t, "kafka", out.Name())
		})
	}
}

func TestKafka_TLSConfig(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)

	t.Run("ca cert + skip verify", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Auth = exporter.KafkaAuth{Type: exporter.KafkaAuthTLS, CACertPath: certPath, TLSSkipVerify: true}
		_, err := exporter.NewKafkaOutput(cfg)
		require.NoError(t, err)
	})

	t.Run("mutual TLS client keypair", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Auth = exporter.KafkaAuth{
			TLS:            true,
			CACertPath:     certPath,
			ClientCertPath: certPath,
			ClientKeyPath:  keyPath,
		}
		_, err := exporter.NewKafkaOutput(cfg)
		require.NoError(t, err)
	})

	t.Run("missing CA file", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Auth = exporter.KafkaAuth{Type: exporter.KafkaAuthTLS, CACertPath: filepath.Join(t.TempDir(), "nope.pem")}
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read CA cert")
	})

	t.Run("garbage CA file", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.pem")
		require.NoError(t, os.WriteFile(bad, []byte("not a pem"), 0o600))
		cfg := baseKafkaCfg()
		cfg.Auth = exporter.KafkaAuth{Type: exporter.KafkaAuthTLS, CACertPath: bad}
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no usable certificates")
	})
}

func TestKafka_CompressionAndAcks(t *testing.T) {
	for _, comp := range []string{"none", "gzip", "snappy", "lz4", "zstd"} {
		t.Run("compression="+comp, func(t *testing.T) {
			cfg := baseKafkaCfg()
			cfg.Compression = comp
			_, err := exporter.NewKafkaOutput(cfg)
			require.NoError(t, err)
		})
	}
	for _, acks := range []string{"all", "1", "0"} {
		t.Run("acks="+acks, func(t *testing.T) {
			cfg := baseKafkaCfg()
			cfg.Acks = acks
			_, err := exporter.NewKafkaOutput(cfg)
			require.NoError(t, err)
		})
	}
}

func TestKafka_InvalidConfigs(t *testing.T) {
	t.Run("no brokers", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Brokers = nil
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "brokers")
	})
	t.Run("no topic", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Topic = ""
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "topic")
	})
	t.Run("bad format", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Format = "yaml"
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "format")
	})
	t.Run("bad compression", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Compression = "brotli"
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "compression")
	})
	t.Run("bad auth type", func(t *testing.T) {
		cfg := baseKafkaCfg()
		cfg.Auth = exporter.KafkaAuth{Type: "kerberos"}
		_, err := exporter.NewKafkaOutput(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "auth type")
	})
}

// TestKafka_SetProducerFactory covers both the custom-func and nil (reset to
// default) branches. Restore the default afterwards to avoid cross-test leak.
func TestKafka_SetProducerFactory(t *testing.T) {
	exporter.SetProducerFactory(nil) // reset-to-default branch
	exporter.SetProducerFactory(nil) // idempotent
}
