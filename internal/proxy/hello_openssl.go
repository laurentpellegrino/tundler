package proxy

import (
	utls "github.com/refraction-networking/utls"
)

// HelloOpenSSL3 is the ClientHello of curl 8.5 linked against OpenSSL 3.0
// (JA3 771,4866-4867-4865-…-47-255,0-11-10-16-22-23-49-13-43-45-51-21,…;
// JA4 t13d3112h2_e8f1e7e78f70_b26ce05bbdd6), captured on 2026-10-24 from the
// tundler image's own curl. It is the fingerprint of every curl, python
// requests/urllib3, php, ruby and wget build on an OpenSSL-3 distro, so an
// edge cannot blocklist it without cutting off a large share of its
// legitimate API clients. The client's User-Agent is kept (no profile UA).
var HelloOpenSSL3 = utls.ClientHelloID{Client: "OpenSSL", Version: "3.0"}

// customSpecs maps a custom ClientHelloID (by its Str() form) to the spec
// builder HandshakeAs applies on top of utls.HelloCustom.
var customSpecs = map[string]func() *utls.ClientHelloSpec{
	HelloOpenSSL3.Str(): openSSL3Spec,
}

func openSSL3Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12,
		TLSVersMax: utls.VersionTLS13,
		CipherSuites: []uint16{
			0x1302, 0x1303, 0x1301, // TLS 1.3: AES-256-GCM, CHACHA20, AES-128-GCM
			0xc02c, 0xc030, 0x009f, // ECDHE-ECDSA/ECDHE-RSA/DHE-RSA AES-256-GCM
			0xcca9, 0xcca8, 0xccaa, // ECDHE-ECDSA/ECDHE-RSA/DHE-RSA CHACHA20
			0xc02b, 0xc02f, 0x009e, // ECDHE-ECDSA/ECDHE-RSA/DHE-RSA AES-128-GCM
			0xc024, 0xc028, 0x006b, // AES-256-CBC-SHA384 / SHA256
			0xc023, 0xc027, 0x0067, // AES-128-CBC-SHA256
			0xc00a, 0xc014, 0x0039, // AES-256-CBC-SHA
			0xc009, 0xc013, 0x0033, // AES-128-CBC-SHA
			0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, // RSA kx
			0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0, 1, 2}},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{
				utls.X25519, utls.CurveP256, utls.CurveID(30), utls.CurveP521, utls.CurveP384,
				utls.CurveID(256), utls.CurveID(257), utls.CurveID(258), utls.CurveID(259), utls.CurveID(260),
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.GenericExtension{Id: 22}, // encrypt_then_mac
			&utls.ExtendedMasterSecretExtension{},
			&utls.GenericExtension{Id: 49}, // post_handshake_auth
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.ECDSAWithP384AndSHA384, utls.ECDSAWithP521AndSHA512,
				utls.Ed25519, utls.SignatureScheme(0x0808), // ed448
				utls.SignatureScheme(0x0809), utls.SignatureScheme(0x080a), utls.SignatureScheme(0x080b), // rsa_pss_pss_*
				utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512,
				utls.PKCS1WithSHA256, utls.PKCS1WithSHA384, utls.PKCS1WithSHA512,
				utls.SignatureScheme(0x0303), utls.SignatureScheme(0x0301), utls.SignatureScheme(0x0302), // legacy sha224
				utls.SignatureScheme(0x0402), utls.SignatureScheme(0x0502), utls.SignatureScheme(0x0602), // dsa
			}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}
}
