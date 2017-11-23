package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	// Hostnameを取得
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalln("Cannot get Hostname")
	}
	// 証明書がなかったら作成
	cert := fmt.Sprintf("%s.cer.pem", hostname)
	priv := fmt.Sprintf("%s.key.pem", hostname)

	if IsExistCertificate(cert, priv) == false {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalln("Cannot get Hostname")
		}

		GenerateCertificate(cert, priv, hostname)
	}

	// HTTPSでサーバーを起動
	go func() {
		http.HandleFunc("/", handler)
		http.ListenAndServeTLS(":8080", cert, priv, nil)
	}()

	// 自己証明書なので、Verifyをスキップするhttp.Clientを作成する
	// ただ、TLS通信したいだけなのでいいよね！
	client := NewClient()

	// HTTPSでGETしてみる
	url := fmt.Sprintf("https://%s:8080/", hostname)
	res, err := client.Get(url)
	if err != nil {
		log.Fatalf("Cannot get from %s; %v", url, err)
	}

	// やったね！！
	log.Println(res.StatusCode)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, World")
}

// NewClient create HttpClient for LAN https. this client skip verify
func NewClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// IsExistCertificate check certificate
func IsExistCertificate(crtFile, keyFile string) bool {
	data, err := ioutil.ReadFile(crtFile)
	if err != nil {
		return false
	}

	b, _ := pem.Decode(data)

	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil || time.Now().After(crt.NotAfter) {
		return false
	}

	data, err = ioutil.ReadFile(keyFile)
	if err != nil {
		return false
	}

	b, _ = pem.Decode(data)
	_, err = x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		return false
	}

	return true
}

// GenerateCertificate generate certificate (x509) for TLS
func GenerateCertificate(crtFile, keyFile, hostname string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 256)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{hostname},
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", hostname},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	cert, err := os.Create(crtFile)
	if err != nil {
		return err
	}
	defer cert.Close()

	key, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer key.Close()

	pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pem.Encode(key, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return nil
}
