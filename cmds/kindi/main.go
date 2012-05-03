// Copyright (c) 2012 Uwe Hoffmann. All rights reserved.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/uwedeportivo/shared/kindi"
	"github.com/uwedeportivo/shared/util"
)

const (
	versionStr     = "2.0"
	fileIdentifier = "kindiv2"
)

type KindiMetadata struct {
	Filename        string
	SenderEmail     string
	SenderSignature []byte
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s version %s, Copyright (c) 2012 monsterbagua LLC. All rights reserved.\n", os.Args[0], versionStr)
	fmt.Fprintf(os.Stderr,
		"\tEncrypt:                 %s [-config <dir>] [-server <server url>] "+
			"-to <comma-separated list of gmail addresses> <file>\n",
		os.Args[0])
	fmt.Fprintf(os.Stderr, "\tDecrypt:                 %s [-config <dir>] [-server <server url>] <file>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\tGenerate Kindi Identity: %s [-config <dir>] -generate <gmail address>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nFlag defaults:\n")
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage

	configDir := flag.String("config", "~/.kindi", "path to config directory")
	help := flag.Bool("help", false, "show this message")
	version := flag.Bool("version", false, "show version")
	to := flag.String("to", "", "comma-separated list of recipient gmail addresses")
	generateEmail := flag.String("generate", "", "gmail address")
	server := flag.String("server", "https://kindimonster.appspot.com/rpc/v1", "server url for fetching certificates")

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	if *version {
		fmt.Fprintf(os.Stderr, "%s version %s, Copyright (c) 2012 monsterbagua LLC. All rights reserved.\n", os.Args[0], versionStr)
		os.Exit(0)
	}

	if len(*configDir) > 0 {
		fmt.Println("Using", *configDir, "for kindi identity.")
	}

	kindipath, err := mkKindiDir(*configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't use kindi directory %s:\n %v\n", *configDir, err)
		os.Exit(1)
	}

	if len(*generateEmail) > 0 {
		fmt.Println("Generating kindi identity for", *generateEmail)

		err = generate(kindipath, *generateEmail)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't generate kindi identity for %s:\n %v\n", *generateEmail, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	me, err := readKindiIdentity(kindipath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read kindi identity from directory %s:\n %v\n", kindipath, err)
		os.Exit(1)
	}

	args := flag.Args()

	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Error:\n Expected filename command line argument (which file to encrypt or decrypt).\n")
		flag.Usage()
		os.Exit(1)
	}

	if len(*to) > 0 {
		fmt.Println("Encrypting", args[0], "for", *to)
		err = encrypt(me, *to, args[0], *server)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Couldn't encrypt file %s for %s:\n %v\n", args[0], *to, err)
			os.Exit(1)
		}
		fmt.Println("Finished. Encrypted file is", args[0]+".kindi")
		os.Exit(0)
	}

	fmt.Println("Decrypting", args[0])
	decryptedFilename, sender, err := decrypt(me, args[0], *server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't decrypt file %s:\n %v\n", args[0], err)
		os.Exit(1)
	}
	fmt.Println("Finished. Decrypted file from", sender, "is", decryptedFilename)
	os.Exit(0)
}

func generate(kindipath, email string) error {
	meKeyPath := filepath.Join(kindipath, "me_key.pem")
	meCertPath := filepath.Join(kindipath, "me_cert.pem")
	mePath := filepath.Join(kindipath, "me")

	userOut, err := os.OpenFile(mePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer userOut.Close()

	_, err = userOut.Write([]byte(email))
	if err != nil {
		return err
	}

	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName:   "kindi",
			Organization: []string{"monsterbagua.com"},
		},
		NotBefore: now.Add(-300).UTC(),
		NotAfter:  now.AddDate(1, 0, 0).UTC(), // valid for 1 year.

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(meCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile(meKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return nil
}

func fetchCertificates(server, recipientEmails string) ([]*rsa.PublicKey, []string, error) {
	u := server + "?emails=" + url.QueryEscape(recipientEmails)

	foundByEmail := make(map[string]int)
	emails := strings.Split(recipientEmails, ",")

	for _, email := range emails {
		foundByEmail[email] = -1
	}

	resp, err := http.Get(u)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	jsonBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	jsonKindiCerts := make([]kindi.JSONKindiCertificate, 0)
	err = json.Unmarshal(jsonBody, &jsonKindiCerts)
	if err != nil {
		return nil, nil, err
	}

	keys := make([]*rsa.PublicKey, len(jsonKindiCerts))
	for i, jsonKindiCert := range jsonKindiCerts {
		cert, err := parseCertificate(jsonKindiCert.Bytes)
		if err != nil {
			return nil, nil, err
		}
		keys[i] = cert
		foundByEmail[jsonKindiCert.Email] = 1
	}

	missing := make([]string, 0)

	for email, found := range foundByEmail {
		if found == -1 {
			missing = append(missing, email)
		}
	}
	return keys, missing, nil
}

func decrypt(me *kindi.Identity, filename, server string) (string, string, error) {
	r, err := os.Open(filename)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	fid := make([]byte, len([]byte(fileIdentifier)))
	_, err = io.ReadFull(r, fid)
	if err != nil {
		return "", "", err
	}

	if string(fid) != fileIdentifier {
		return "", "", fmt.Errorf("file identifier mismatch for file %s. expected %s but got %s", filename, fileIdentifier, string(fid))
	}

	cs, err := me.DecryptCipherStream(r)
	if err != nil {
		return "", "", err
	}

	abtr := util.NewAllButTailReader(r, cs.Hash.Size(), 65536)

	jsonMetadata, err := cs.DecryptMetadata(abtr)
	if err != nil {
		return "", "", err
	}

	var metadata KindiMetadata
	err = json.Unmarshal(jsonMetadata, &metadata)
	if err != nil {
		return "", "", err
	}

	outfilename := filepath.Join(filepath.Dir(filename), metadata.Filename)
	w, err := os.OpenFile(outfilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", err
	}
	defer w.Close()

	err = cs.DecryptPayload(w, abtr)
	if err != nil {
		return "", "", err
	}

	if !bytes.Equal(abtr.Tail(), cs.Hash.Sum(nil)) {
		return "", "", fmt.Errorf("hash mismatch. kindi file %s has been modified.", filename)
	}

	senderCerts, _, err := fetchCertificates(server, metadata.SenderEmail)
	err = kindi.VerifySignature(metadata.SenderEmail, metadata.SenderSignature, senderCerts)
	if err != nil {
		return "", "", fmt.Errorf("sender signature for %s did not verify.", metadata.SenderEmail)
	}

	return outfilename, metadata.SenderEmail, nil
}

func encrypt(me *kindi.Identity, recipientEmails, filename, server string) error {
	certs, missing, err := fetchCertificates(server, recipientEmails)
	if err != nil {
		return err
	}

	if len(certs) == 0 {
		fmt.Fprintf(os.Stderr, "----------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Warning: Couldn't find certificates for the following recipients: [%v]\n", recipientEmails)
		fmt.Fprintf(os.Stderr, "Those recipients will not be able to decrypt the file.\n")
		fmt.Fprintf(os.Stderr, "Please go to https://kindimonster.appspot.com/invite and invite them to join kindi.\n")
		fmt.Fprintf(os.Stderr, "----------------------------------------------------\n")

		return errors.New("no certificates fetched")
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "----------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Warning: Couldn't find certificates for the following recipients: %v\n", missing)
		fmt.Fprintf(os.Stderr, "Those recipients will not be able to decrypt the file.\n")
		fmt.Fprintf(os.Stderr, "Please go to https://kindimonster.appspot.com/invite and invite them to join kindi.\n")
		fmt.Fprintf(os.Stderr, "----------------------------------------------------\n")
	}

	r, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer r.Close()

	w, err := os.OpenFile(filename+".kindi", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write([]byte(fileIdentifier))
	if err != nil {
		return err
	}

	sig, err := me.Sign()
	if err != nil {
		return err
	}

	metadata := KindiMetadata{
		Filename:        filepath.Base(filename),
		SenderEmail:     me.Email,
		SenderSignature: sig,
	}
	jsonMetadata, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	return me.Encrypt(w, jsonMetadata, r, certs)
}

func readKindiIdentity(kindipath string) (*kindi.Identity, error) {
	meKeyPath := filepath.Join(kindipath, "me_key.pem")
	mePath := filepath.Join(kindipath, "me")

	rKey, err := os.Open(meKeyPath)
	if err != nil {
		return nil, err
	}
	defer rKey.Close()

	keyBytes, err := ioutil.ReadAll(rKey)
	if err != nil {
		return nil, err
	}

	key, err := parseKey(keyBytes)
	if err != nil {
		return nil, err
	}

	rMe, err := os.Open(mePath)
	if err != nil {
		return nil, err
	}
	defer rMe.Close()

	meBytes, err := ioutil.ReadAll(rMe)
	if err != nil {
		return nil, err
	}

	return &kindi.Identity{
		Email:      string(meBytes),
		PrivateKey: key,
	}, nil
}

func parsePem(pemBytes []byte) (*pem.Block, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("Failed to decode pem")
	}
	return pemBlock, nil
}

func parseCertificate(certBytes []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return nil, fmt.Errorf("x509 algorithm %v not supported", cert.PublicKeyAlgorithm)
	}

	rsaPub, _ := cert.PublicKey.(*rsa.PublicKey)

	return rsaPub, nil
}

func parseKey(keyBytes []byte) (*rsa.PrivateKey, error) {
	pemBlock, err := parsePem(keyBytes)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
}

func mkKindiDir(path string) (string, error) {
	var name string

	if len(path) == 0 || path == "~/.kindi" {
		uid := syscall.Getuid()
		uid_str := strconv.Itoa(uid)
		u, err := user.LookupId(uid_str)
		if err != nil {
			return "", err
		}
		if e, g := uid_str, u.Uid; e != g {
			return "", fmt.Errorf("expected Uid of %d; got %d", e, g)
		}
		fi, err := os.Stat(u.HomeDir)
		if err != nil || !fi.IsDir() {
			return "", fmt.Errorf("expected a valid HomeDir; stat(%q): err=%v, IsDirectory=%v", err, fi.IsDir())
		}

		name = filepath.Join(u.HomeDir, ".kindi")
	} else {
		name = path
	}

	err := os.Mkdir(name, 0700)
	if err != nil {
		if pe, ok := err.(*os.PathError); ok && pe.Err == syscall.EEXIST {
			return name, nil
		}
		return "", err
	}
	return name, nil
}
