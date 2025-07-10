package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"net/url"

	"encoding/base64"

	"github.com/miekg/dns"
	utls "github.com/refraction-networking/utls"
)

var (
	hostRules        = make(map[string]string)
	hostResolver     = make(map[string]string)
	resolveRules     = make(map[string]string)
	insecure         = flag.Bool("k", false, "Ignore certificate errors")
	headOnly         = flag.Bool("I", false, "Fetch only headers")
	verbose          = flag.Bool("v", false, "Enable verbose logging for TLS handshake, packets, and ClientHello details")
	generateCert     = flag.Bool("generate-cert", true, "Generate a self-signed certificate for the spoofed SNI")
	followRedirects  = flag.Bool("L", false, "Follow HTTP redirects")
	help             = flag.Bool("help", false, "Display usage information")
	requestURL       string
	certPool         *x509.CertPool
	generatedCert    *x509.Certificate
	enableSNIRewrite bool
)

func init() {
	flag.Func("host-rules", "Rewrite host and enable SNI spoofing with Chrome TLS fingerprint (e.g., www.google.com=v.com)", func(s string) error {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format for --host-rules, example: gcurl -k -I --host-rules=www.google.com=v.com --host-resolver-rules=v.com=172.67.35.211 https://www.google.com")
		}
		hostRules[parts[0]] = parts[1]
		return nil
	})
	flag.Func("host-resolver-rules", "Resolve spoofed host to real IP", func(s string) error {
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid format for --host-resolver-rules")
		}
		hostResolver[parts[0]] = parts[1]
		return nil
	})
	flag.Func("resolve", "Force resolve HOST:PORT:ADDR (like curl --resolve, can be specified multiple times)", func(s string) error {
		parts := strings.Split(s, ":")
		if len(parts) < 3 {
			return fmt.Errorf("invalid format for --resolve, expected HOST:PORT:ADDR")
		}
		hostPort := parts[0] + ":" + parts[1]
		ip := parts[2]
		resolveRules[hostPort] = ip
		return nil
	})
}

// generateSelfSignedCert creates a self-signed certificate for the given hostname
func generateSelfSignedCert(hostname string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if *verbose {
		log.Printf("[VERBOSE] Generating self-signed certificate for hostname=%s", hostname)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"gcurl Self-Signed"},
			CommonName:   hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	if *verbose {
		log.Printf("[VERBOSE] Generated certificate: Subject=%s, SANs=%v, NotAfter=%s", cert.Subject, cert.DNSNames, cert.NotAfter)
	}

	return cert, priv, nil
}

// customDial handles the TCP connection with optional verbose logging
func customDial(network, addr string, serverName string, snRewrite bool, fakeName string, fallback bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Apply resolve rules first
	if ip, ok := resolveRules[host+":"+port]; ok {
		if *verbose {
			log.Printf("[VERBOSE] Applying resolve rule: %s:%s -> %s", host, port, ip)
		}
		addr = net.JoinHostPort(ip, port)
	} else if snRewrite && !fallback {
		if ip, ok := hostResolver[fakeName]; ok {
			if *verbose {
				log.Printf("[VERBOSE] Applying host resolver rule for spoofed SNI: %s -> %s", fakeName, ip)
			}
			addr = net.JoinHostPort(ip, port)
		} else if *verbose {
			log.Printf("[VERBOSE] No host resolver rule found for spoofed SNI: %s, using original addr=%s", fakeName, addr)
		}
	} else {
		if ip, ok := hostResolver[serverName]; ok {
			if *verbose {
				log.Printf("[VERBOSE] Applying host resolver rule for serverName: %s -> %s", serverName, ip)
			}
			addr = net.JoinHostPort(ip, port)
		} else if *verbose {
			log.Printf("[VERBOSE] No host resolver rule found for serverName: %s, using original addr=%s", serverName, addr)
		}
	}

	if *verbose {
		log.Printf("[VERBOSE] Dialing TCP: network=%s, addr=%s", network, addr)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	if *verbose {
		log.Printf("[VERBOSE] TCP connection established: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	}

	return conn, nil
}

// getClientHelloID determines the TLS fingerprint based on host-rules
func getClientHelloID(serverName string, echConfigBytes []byte) utls.ClientHelloID {
	if len(echConfigBytes) > 0 {
		return utls.HelloGolang // ECH 成功，使用原生 ClientHello
	}
	if _, ok := hostRules[serverName]; ok {
		return utls.HelloChrome_Auto // host-rules 时伪造 Chrome fingerprint
	}
	return utls.HelloGolang // 默认
}

// fetchECHConfigBytes queries DNS HTTPS record for ECHConfig using 223.5.5.5 and returns the raw bytes
func fetchECHConfigBytes(domain string) ([]byte, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	r, _, err := c.Exchange(m, "223.5.5.5:53")
	if err != nil {
		return nil, err
	}
	for _, ans := range r.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, param := range https.Value {
				if *verbose {
					fmt.Printf("[DEBUG] param: %+v, type: %T\n", param, param)
				}
				if param.Key() == 5 {
					var echBytes []byte
					if v, ok := getFieldBytes(param, "Value"); ok {
						echBytes = v
					} else if d, ok := getFieldBytes(param, "Data"); ok {
						echBytes = d
					} else if s := param.String(); s != "" {
						if *verbose {
							fmt.Printf("[DEBUG] Trying base64 decode of param.String(): %s\n", s)
						}
						b64 := s
						data, err := base64.StdEncoding.DecodeString(b64)
						if err != nil {
							data, err = base64.RawURLEncoding.DecodeString(b64)
						}
						if err == nil && len(data) > 0 {
							if *verbose {
								fmt.Printf("[DEBUG] base64 decode success, len=%d\n", len(data))
							}
							echBytes = data
						}
					}
					if len(echBytes) > 0 {
						if *verbose {
							// 解析并打印 ECHConfigList 详细内容
							cfgs, err := utls.UnmarshalECHConfigs(echBytes)
							if err != nil {
								fmt.Printf("[VERBOSE] Failed to parse ECHConfigList: %v\n", err)
							} else {
								fmt.Printf("[VERBOSE] ECHConfigList contains %d configs:\n", len(cfgs))
								for i, cfg := range cfgs {
									fmt.Printf("[VERBOSE]   Config[%d]: %+v\n", i, cfg)
								}
							}
						}
						return echBytes, nil
					}
					if *verbose {
						fmt.Printf("[DEBUG] ECH param found but no Value/Data field, and base64 decode failed: %+v\n", param)
					}
				}
			}
		}
	}
	return nil, nil // not found
}

// getFieldBytes 用反射获取字段名为 name 的 []byte 字段
func getFieldBytes(obj interface{}, name string) ([]byte, bool) {
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	field := val.FieldByName(name)
	if field.IsValid() && field.Kind() == reflect.Slice && field.Type().Elem().Kind() == reflect.Uint8 {
		return field.Bytes(), true
	}
	return nil, false
}

// newUTLSConn creates a TLS connection with verbose logging and fingerprint spoofing
func newUTLSConn(network, addr string, serverName string, fallback bool, clientHelloID utls.ClientHelloID, echConfigBytes []byte) (net.Conn, error) {
	// 移除 SNI 伪造逻辑，只用 main() 传入的 serverName
	if *verbose {
		log.Printf("[VERBOSE] Using ServerName=%q (fallback=%v)", serverName, fallback)
	}

	conn, err := customDial(network, addr, serverName, false, "", fallback)
	if err != nil {
		return nil, err
	}

	var verifyFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	if *generateCert && !fallback && !*insecure {
		if certPool == nil {
			certPool = x509.NewCertPool()
			var priv *rsa.PrivateKey
			generatedCert, priv, err = generateSelfSignedCert(serverName)
			if err != nil {
				return nil, fmt.Errorf("failed to generate certificate: %v", err)
			}
			certPool.AddCert(generatedCert)

			if *verbose {
				certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generatedCert.Raw})
				privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
				log.Printf("[VERBOSE] Generated Certificate PEM:\n%s", string(certPEM))
				log.Printf("[VERBOSE] Generated Private Key PEM:\n%s", string(privPEM))
			}
		}

		verifyFunc = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if *verbose {
				log.Printf("[VERBOSE] Verifying server certificate against generated certificate for %s", serverName)
			}
			opts := x509.VerifyOptions{
				DNSName:       serverName,
				Roots:         certPool,
				CurrentTime:   time.Now(),
				Intermediates: x509.NewCertPool(),
			}

			for _, rawCert := range rawCerts[1:] {
				cert, err := x509.ParseCertificate(rawCert)
				if err == nil {
					opts.Intermediates.AddCert(cert)
				}
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse server certificate: %v", err)
			}

			if *verbose {
				log.Printf("[VERBOSE] Server Certificate: Subject=%s, SANs=%v", cert.Subject, cert.DNSNames)
			}

			_, err = cert.Verify(opts)
			if err != nil {
				if *verbose {
					log.Printf("[VERBOSE] Certificate verification failed: %v", err)
				}
				return err
			}

			if *verbose {
				log.Printf("[VERBOSE] Certificate verification succeeded")
			}
			return nil
		}
	}

	// 修正：如果启用 ECH，MinVersion 必须为 TLS1.3
	var minVersion uint16 = utls.VersionTLS12
	if len(echConfigBytes) > 0 {
		minVersion = utls.VersionTLS13
	}

	config := &utls.Config{
		InsecureSkipVerify:             *insecure,
		ServerName:                     serverName,
		MinVersion:                     minVersion,
		MaxVersion:                     utls.VersionTLS13,
		VerifyPeerCertificate:          verifyFunc,
		EncryptedClientHelloConfigList: echConfigBytes,
	}

	uConn := utls.UClient(conn, config, clientHelloID)
	if *verbose {
		fingerprint := "golang (default)"
		if len(hostRules) > 0 {
			fingerprint = "chrome (default)"
		}
		log.Printf("[VERBOSE] TLS Client Hello Details (Fingerprint: %s):", fingerprint)
		// Access ClientHelloSpec directly

		if uConn.ClientHelloSpec != nil {
			log.Printf("[VERBOSE]   Cipher Suites: %v", getCipherSuites(uConn.ClientHelloSpec.CipherSuites))
			log.Printf("[VERBOSE]   Extensions: %v", getExtensions(uConn.ClientHelloSpec.Extensions))
			log.Printf("[VERBOSE]   Supported Curves: %v", getSupportedCurves(uConn.ClientHelloSpec.SupportedCurves))
			log.Printf("[VERBOSE]   Supported Points: %v", getSupportedPoints(uConn.ClientHelloSpec.SupportedPoints))
		} else {
			log.Printf("[VERBOSE]   Cipher Suites: [Not available before handshake]")
			log.Printf("[VERBOSE]   Extensions: [Not available before handshake]")
			log.Printf("[VERBOSE]   Supported Curves: [Not available before handshake]")
			log.Printf("[VERBOSE]   Supported Points: [Not available before handshake]")
		}
		log.Printf("[VERBOSE]   Supported Versions: %v", getSupportedVersions(config.MinVersion, config.MaxVersion))
		log.Printf("[VERBOSE]   ServerName=%s", serverName)
	}

	if err := uConn.Handshake(); err != nil {
		conn.Close()
		if *verbose {
			log.Printf("[VERBOSE] TLS Handshake failed: %v", err)
		}
		if fallback {
			if *verbose {
				log.Printf("[VERBOSE] Retrying with original SNI: %s", serverName)
			}
			return newUTLSConn(network, addr, serverName, true, clientHelloID, echConfigBytes)
		}
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	if *verbose {
		state := uConn.ConnectionState()
		log.Printf("[VERBOSE] TLS Handshake completed: Version=%s, CipherSuite=%s, ServerName=%s",
			tlsVersionToString(state.Version), cipherSuiteToString(state.CipherSuite), state.ServerName)
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			log.Printf("[VERBOSE] Server Certificate: Subject=%s, Issuer=%s, SANs=%v",
				cert.Subject, cert.Issuer, cert.DNSNames)
		} else {
			log.Printf("[VERBOSE] No server certificates received")
		}
	}

	return uConn, nil
}

// Helper function to convert TLS version to string
func tlsVersionToString(version uint16) string {
	switch version {
	case utls.VersionTLS13:
		return "TLS1.3"
	case utls.VersionTLS12:
		return "TLS1.2"
	case utls.VersionTLS11:
		return "TLS1.1"
	case utls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("Unknown(%d)", version)
	}
}

// Helper function to convert cipher suite to string
func cipherSuiteToString(cipherSuite uint16) string {
	switch cipherSuite {
	case 0x1301:
		return "TLS_AES_128_GCM_SHA256"
	case 0x1302:
		return "TLS_AES_256_GCM_SHA384"
	case 0x1303:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case 0xC02F:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case 0xC030:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	default:
		return fmt.Sprintf("Unknown(0x%x)", cipherSuite)
	}
}

// Helper functions for verbose ClientHello logging
func getCipherSuites(cipherSuites []uint16) []string {
	var suites []string
	for _, suite := range cipherSuites {
		suites = append(suites, cipherSuiteToString(suite))
	}
	return suites
}

func getExtensions(extensions []utls.TLSExtension) []string {
	var extNames []string
	for _, ext := range extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			extNames = append(extNames, "SNI")
		case *utls.SupportedCurvesExtension:
			extNames = append(extNames, "SupportedCurves")
		case *utls.SupportedPointsExtension:
			extNames = append(extNames, "SupportedPoints")
		case *utls.SessionTicketExtension:
			extNames = append(extNames, "SessionTicket")
		case *utls.ALPNExtension:
			extNames = append(extNames, fmt.Sprintf("ALPN(%v)", e.AlpnProtocols))
		case *utls.SignatureAlgorithmsExtension:
			extNames = append(extNames, "SignatureAlgorithms")
		case *utls.KeyShareExtension:
			keyShares := make([]string, len(e.KeyShares))
			for i, ks := range e.KeyShares {
				keyShares[i] = fmt.Sprintf("CurveID=%d", ks.Group)
			}
			extNames = append(extNames, fmt.Sprintf("KeyShare(%v)", keyShares))
		default:
			extNames = append(extNames, fmt.Sprintf("Unknown(%T)", e))
		}
	}
	return extNames
}

func getSupportedVersions(minVersion, maxVersion uint16) []string {
	versions := []uint16{minVersion}
	if maxVersion > minVersion {
		for v := minVersion + 1; v <= maxVersion; v++ {
			versions = append(versions, v)
		}
	}
	var vers []string
	for _, v := range versions {
		vers = append(vers, tlsVersionToString(v))
	}
	return vers
}

func getSupportedCurves(curves []utls.CurveID) []string {
	var curveNames []string
	for _, c := range curves {
		switch c {
		case utls.CurveP256:
			curveNames = append(curveNames, "P-256")
		case utls.CurveP384:
			curveNames = append(curveNames, "P-384")
		case utls.CurveP521:
			curveNames = append(curveNames, "P-521")
		case utls.X25519:
			curveNames = append(curveNames, "X25519")
		default:
			curveNames = append(curveNames, fmt.Sprintf("Unknown(%d)", c))
		}
	}
	return curveNames
}

func getSupportedPoints(points []uint8) []string {
	var pointNames []string
	for _, p := range points {
		switch p {
		case 0:
			pointNames = append(pointNames, "Uncompressed")
		case 1:
			pointNames = append(pointNames, "ANSI X9.62 Compressed Prime")
		case 2:
			pointNames = append(pointNames, "ANSI X9.62 Compressed Char2")
		default:
			pointNames = append(pointNames, fmt.Sprintf("Unknown(%d)", p))
		}
	}
	return pointNames
}

// newCustomTransport creates a custom HTTP transport
func newCustomTransport(sniServerName string, clientHelloID utls.ClientHelloID, echConfigBytes []byte) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if *verbose {
				log.Printf("[VERBOSE] DialTLSContext: network=%s, addr=%s, sniServerName=%s", network, addr, sniServerName)
			}
			return newUTLSConn(network, addr, sniServerName, false, clientHelloID, echConfigBytes)
		},
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
	}
}

func main() {
	flag.Parse()

	if *help {
		fmt.Println("gcurl - A curl-like tool with TLS fingerprinting and SNI spoofing capabilities")
		fmt.Println("Usage: gcurl [OPTIONS] URL")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nNotes:")
		fmt.Println("  - Using --host-rules automatically enables SNI spoofing and Chrome TLS fingerprint.")
		fmt.Println("  - --resolve works like curl: --resolve HOST:PORT:IP can be specified multiple times to force DNS resolution.")
		fmt.Println("\nExamples:")
		fmt.Println("  gcurl https://www.example.com")
		fmt.Println("  gcurl -k -I https://www.example.com")
		fmt.Println("  gcurl -v --host-rules=www.google.com=v.com --host-resolver-rules=v.com=172.67.35.211 --resolve=www.google.com:443:1.2.3.4 https://www.google.com")
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		log.Fatal("Usage: gcurl [OPTIONS] URL")
	}
	requestURL = args[0]
	// 禁止 http 访问（明文 ClientHello），如果启用 host-rules
	if len(hostRules) > 0 {
		parsed, err := url.Parse(requestURL)
		if err != nil {
			log.Fatalf("Invalid URL: %v", err)
		}
		if parsed.Scheme != "https" {
			log.Fatalf("HTTP (non-TLS) requests are disabled when --host-rules is set. Refusing to send plaintext ClientHello.")
		}
	}

	// main() 里，判断是否需要用 resolveRules 的 IP
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		log.Fatalf("Invalid URL: %v", err)
	}
	origHost := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostPort := origHost + ":" + port

	echConfigBytes, _ := fetchECHConfigBytes(origHost)
	var clientHelloID utls.ClientHelloID
	var sniServerName string
	var connectAddr string
	if len(echConfigBytes) > 0 {
		clientHelloID = utls.HelloGolang
		sniServerName = origHost
		connectAddr = net.JoinHostPort(origHost, port)
		if *verbose {
			log.Printf("[VERBOSE] Using ECH for original host %s, not spoofing ClientHello", origHost)
		}
	} else if ip, ok := resolveRules[hostPort]; ok {
		// 没有 ECH，且 --resolve 命中，直接用 IP，不伪造 SNI/ClientHello
		clientHelloID = utls.HelloGolang
		sniServerName = "" // 不发 SNI
		connectAddr = net.JoinHostPort(ip, port)
		if *verbose {
			log.Printf("[VERBOSE] No ECH, using --resolve IP %s for %s, not spoofing ClientHello/SNI", ip, hostPort)
		}
	} else {
		// fallback: 伪造 SNI 和 ClientHello
		fakeName, snRewrite := hostRules[origHost]
		if snRewrite {
			clientHelloID = utls.HelloChrome_Auto
			sniServerName = fakeName
			connectAddr = net.JoinHostPort(fakeName, port)
			if *verbose {
				log.Printf("[VERBOSE] ECH not found for %s, spoofing ClientHello for %s", origHost, fakeName)
			}
		} else {
			clientHelloID = utls.HelloGolang
			sniServerName = origHost
			connectAddr = net.JoinHostPort(origHost, port)
		}
	}

	// Automatically enable SNI rewriting if host-rules is provided
	if len(hostRules) > 0 {
		enableSNIRewrite = true
	}

	if *verbose {
		log.Printf("[VERBOSE] Starting request: URL=%s, HeadOnly=%v, Insecure=%v, GenerateCert=%v, FollowRedirects=%v, EnableSNIRewrite=%v",
			requestURL, *headOnly, *insecure, *generateCert, *followRedirects, enableSNIRewrite)
		log.Printf("[VERBOSE] Host Rules: %v", hostRules)
		log.Printf("[VERBOSE] Host Resolver Rules: %v", hostResolver)
		log.Printf("[VERBOSE] Resolve Rules: %v", resolveRules)
	}

	client := &http.Client{
		Transport: newCustomTransport(sniServerName, clientHelloID, echConfigBytes),
	}
	if *followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if *verbose {
				log.Printf("[VERBOSE] Following redirect to: %s", req.URL)
			}
			return nil
		}
	} else {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	if *headOnly {
		req.Method = "HEAD"
	}
	// 伪造 SNI 时同步伪造 HTTP Host 头
	//if enableSNIRewrite {
	//	originalHost := req.URL.Hostname()
	//	if fakeName, ok := hostRules[originalHost]; ok {
	//		req.Host = fakeName
	//		if port := req.URL.Port(); port != "" {
	//			req.Host = fakeName + ":" + port
	//		}
	//	}
	//}

	if *verbose {
		// Create a custom connection to inspect raw response
		// 修正：补全端口并使用伪造 host 逻辑
		// 调用 newUTLSConn 时传递 connectAddr 作为 addr
		uConn, err := newUTLSConn("tcp", connectAddr, sniServerName, false, clientHelloID, echConfigBytes)
		log.Printf("[VERBOSE] HTTP Request Host header: %s", req.Host)
		if err != nil {
			log.Printf("[VERBOSE] Failed to establish TLS connection: %v", err)
		} else {
			defer uConn.Close()
			// Send a simple HTTP request manually
			rawRequest := fmt.Sprintf(
				"%s %s HTTP/1.1\r\n"+
					"Host: %s\r\n"+
					"User-Agent: gcurl/1.0\r\n"+
					"Accept: */*\r\n"+
					"Connection: close\r\n"+
					"Accept-Encoding: identity\r\n\r\n",
				req.Method, req.URL.RequestURI(), req.Host)
			_, err = uConn.Write([]byte(rawRequest))
			if err != nil {
				log.Printf("[VERBOSE] Failed to send raw request: %v", err)
			} else {
				buf := make([]byte, 1024)
				n, err := uConn.Read(buf)
				if err != nil && err != io.EOF {
					log.Printf("[VERBOSE] Failed to read raw response: %v", err)
				} else {
					log.Printf("[VERBOSE] Raw server response: %q", buf[:n])
				}
			}
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		if *verbose {
			if resp != nil && resp.Body != nil {
				buf := new(bytes.Buffer)
				_, readErr := io.CopyN(buf, resp.Body, 1024)
				if readErr != nil && readErr != io.EOF {
					log.Printf("[VERBOSE] Failed to read raw response data: %v", readErr)
				} else {
					log.Printf("[VERBOSE] Raw response data (first 1024 bytes): %q", buf.Bytes())
				}
				resp.Body.Close()
			} else {
				log.Printf("[VERBOSE] No response body available")
			}
		}
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP/%d.%d %d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)
	for k, v := range resp.Header {
		fmt.Printf("%s: %s\n", k, strings.Join(v, ", "))
	}
	if !*headOnly {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Failed to read response body: %v", err)
		} else {
			fmt.Printf("\n%s\n", body)
		}
	}
}
