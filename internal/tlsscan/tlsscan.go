package tlsscan

import (
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"time"

	utls "github.com/refraction-networking/utls"
)

// probeTimeout bounds each individual handshake attempt. It's shorter than the 10s
// requestTimeout used elsewhere for full HTTP requests because a version/cipher a server
// doesn't support is normally rejected within a single round trip, not a slow response.
const probeTimeout = 5 * time.Second

// scanVersions are the pre-TLS-1.3 versions probed with the standard library, which honors
// tls.Config.CipherSuites for these. TLS 1.3 is handled separately (see scanTLS13) because the
// standard library ignores CipherSuites for it -- the client always offers its fixed built-in
// set and lets the server choose, so individual TLS 1.3 ciphers can't be probed this way.
var scanVersions = []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}

// tls13CipherSuites are the mainstream TLS 1.3 suites real servers negotiate. The RFC also
// defines TLS_AES_128_CCM_SHA256/TLS_AES_128_CCM_8_SHA256, but those are essentially IoT-only
// and are skipped to keep the scan focused on what's actually relevant to a web server audit.
var tls13CipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

// versionNames gives each version a display name, since crypto/tls has no exported
// human-readable name for pre-1.3 versions (tls.VersionName only covers 1.3+ in some Go
// versions) and this keeps the table's labels independent of stdlib's own formatting choices.
var versionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// deprecatedVersions are the versions RFC 8996 formally deprecates.
var deprecatedVersions = map[uint16]bool{
	tls.VersionTLS10: true,
	tls.VersionTLS11: true,
}

// CipherResult is the outcome of probing one cipher suite against one TLS version.
type CipherResult struct {
	CipherID   uint16
	CipherName string

	// Insecure mirrors tls.CipherSuite.Insecure -- true for suites with known weaknesses
	// (RC4, 3DES, SHA-1 CBC, etc). Surfacing this on supported ciphers is the point of the scan.
	Insecure bool

	Supported bool
}

// VersionResult is the outcome of probing one TLS version. Ciphers is empty when Supported is
// false -- once a gate probe shows the server rejects a version outright, sweeping every
// individual cipher against it would just be slower ways of learning the same fact.
type VersionResult struct {
	Version     uint16
	VersionName string
	Deprecated  bool
	Supported   bool
	Ciphers     []CipherResult
}

// Result is the full tls-scan report for one target, with Versions ordered TLS 1.0 through 1.3.
type Result struct {
	Host     string
	Port     int
	Versions []VersionResult
}

// Scan connects to host:port and enumerates which TLS versions and cipher suites it accepts.
// insecure mirrors the root --insecure flag, disabling certificate verification the same way
// other commands in this tool do -- a cipher scan cares whether the server will negotiate a
// suite at all, not whether its certificate is trusted.
func Scan(host string, port int, insecure bool) (*Result, error) {
	addr := net.JoinHostPort(host, fmt.Sprint(port))

	probeConn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	probeConn.Close()

	result := &Result{Host: host, Port: port}
	for _, version := range scanVersions {
		result.Versions = append(result.Versions, scanVersion(addr, version, insecure))
	}
	result.Versions = append(result.Versions, scanTLS13(addr, host, insecure))

	return result, nil
}

// scanVersion gates on whether version is supported at all -- offering every candidate cipher
// for that version in one dial -- before sweeping candidates individually. This keeps a scan of
// a modern server, which has TLS 1.0/1.1 disabled, fast without giving up per-cipher detail
// against a legacy server that still accepts them.
func scanVersion(addr string, version uint16, insecure bool) VersionResult {
	result := VersionResult{
		Version:     version,
		VersionName: versionNames[version],
		Deprecated:  deprecatedVersions[version],
	}

	candidates := cipherSuitesFor(version)
	candidateIDs := make([]uint16, len(candidates))
	for i, c := range candidates {
		candidateIDs[i] = c.ID
	}

	if !dialVersion(addr, version, candidateIDs, insecure) {
		return result
	}
	result.Supported = true

	for _, c := range candidates {
		result.Ciphers = append(result.Ciphers, CipherResult{
			CipherID:   c.ID,
			CipherName: c.Name,
			Insecure:   c.Insecure,
			Supported:  dialVersion(addr, version, []uint16{c.ID}, insecure),
		})
	}

	return result
}

// cipherSuitesFor returns every cipher suite crypto/tls can negotiate for version, combining
// tls.CipherSuites() and tls.InsecureCipherSuites() -- the whole point of this scan is surfacing
// legacy/weak ciphers a server still accepts, so they're included alongside the modern ones.
func cipherSuitesFor(version uint16) []*tls.CipherSuite {
	var suites []*tls.CipherSuite
	for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		if slices.Contains(c.SupportedVersions, version) {
			suites = append(suites, c)
		}
	}
	return suites
}

// dialVersion attempts a handshake pinned to version, offering only cipherIDs. A successful
// dial means the server is willing to negotiate at least one of them; any error -- a clean
// protocol rejection or a network-level failure -- is treated as "not supported", since the two
// aren't reliably distinguishable without fragile error-string matching.
func dialVersion(addr string, version uint16, cipherIDs []uint16, insecure bool) bool {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		CipherSuites:       cipherIDs,
		InsecureSkipVerify: insecure,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// scanTLS13 gates on plain TLS 1.3 support via the standard library, then -- only if the gate
// succeeds -- sweeps each mainstream TLS 1.3 cipher individually via utls, since crypto/tls
// itself has no way to force a single candidate into a TLS 1.3 ClientHello.
func scanTLS13(addr string, host string, insecure bool) VersionResult {
	result := VersionResult{
		Version:     tls.VersionTLS13,
		VersionName: versionNames[tls.VersionTLS13],
	}

	if !dialVersion(addr, tls.VersionTLS13, nil, insecure) {
		return result
	}
	result.Supported = true

	for _, id := range tls13CipherSuites {
		result.Ciphers = append(result.Ciphers, CipherResult{
			CipherID:   id,
			CipherName: tls.CipherSuiteName(id),
			Supported:  probeTLS13Cipher(addr, host, id, insecure),
		})
	}

	return result
}

// probeTLS13Cipher attempts a TLS 1.3 handshake offering exactly one cipher suite. crypto/tls
// ignores Config.CipherSuites for TLS 1.3 -- the client always offers its own fixed set and lets
// the server pick -- so this builds a minimal, explicit ClientHello by hand via utls instead of
// relying on any of its browser-mimicry presets, which bundle GREASE and randomization that only
// add noise for a security scan that wants a plain, reproducible per-cipher answer.
func probeTLS13Cipher(addr string, host string, cipherID uint16, insecure bool) bool {
	dialer := &net.Dialer{Timeout: probeTimeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(probeTimeout)); err != nil {
		return false
	}

	spec := &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS13,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       []uint16{cipherID},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: utls.X25519}}},
			&utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13}},
		},
	}

	uconn := utls.UClient(conn, &utls.Config{ServerName: host, InsecureSkipVerify: insecure}, utls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		return false
	}

	return uconn.Handshake() == nil
}
