package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	goflag "flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/pkg/errors"
	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"

	"github.com/couchbaselabs/cbcerthelper"
)

var fConfigPath, fHosts, fHttpUser, fHttpPass, fSshUser, fSshPass, fCertUser, fCertEmail string

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate cluster certificates",
	Run: func(cmd *cobra.Command, args []string) {
		generate()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	if err := goflag.CommandLine.Parse([]string{}); err != nil {
		log.Fatal(err)
	}
	generateCmd.PersistentFlags().StringVar(&fConfigPath, "config", "", "Path to config file")
	generateCmd.PersistentFlags().StringVar(&fHosts, "hosts", "", "Comma separated list of node hosts")
	generateCmd.PersistentFlags().StringVar(&fHttpUser, "http-user", "", "Username to use for communicating with Couchbase over http")
	generateCmd.PersistentFlags().StringVar(&fHttpPass, "http-pass", "", "Password to use for communicating with Couchbase over http")
	generateCmd.PersistentFlags().StringVar(&fSshUser, "ssh-user", "", "Username to use for performing operations on hosts over ssh")
	generateCmd.PersistentFlags().StringVar(&fSshPass, "ssh-pass", "", "Password to use for performing operations on hosts over ssh")
	generateCmd.PersistentFlags().StringVar(&fCertUser, "cert-user", "", "Username to generate certificate for")
	generateCmd.PersistentFlags().StringVar(&fCertEmail, "cert-email", "", "Email address to generate certificate for")

}

func initConfig() {
	// viper.SetConfigType("toml")
	if fConfigPath == "" {
		// use default config file
		viper.SetConfigName(".cbcerthelper")
		viper.AddConfigPath("$HOME/")
	} else {
		// if user specified the config file, use it
		viper.SetConfigFile(fConfigPath)
	}

	viper.SetEnvPrefix("cbcert")
	viper.AutomaticEnv()

	err := viper.ReadInConfig()
	if err != nil {
		// We only care if it's an error due to config not being found
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Fatalf("Failed to read config file: %v", err)
		}
	}

	getStringArg := func(arg string) string {
		if generateCmd.PersistentFlags().Changed(arg) {
			val, _ := generateCmd.PersistentFlags().GetString(arg)
			return val
		}
		return viper.GetString(arg)
	}

	fHosts = getStringArg("hosts")
	fHttpUser = getStringArg("http-user")
	fHttpPass = getStringArg("http-pass")
	fSshUser = getStringArg("ssh-user")
	fSshPass = getStringArg("ssh-pass")
	fCertUser = getStringArg("cert-user")
	fCertEmail = getStringArg("cert-email")
}

func mustBeNotEmpty(key, value string) {
	if value == "" {
		log.Fatalf("Missing required %s parameter", key)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if err := generateCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func generate() {
	mustBeNotEmpty("hosts", fHosts)
	mustBeNotEmpty("http-user", fHttpUser)
	mustBeNotEmpty("http-pass", fHttpPass)
	mustBeNotEmpty("ssh-user", fSshUser)
	mustBeNotEmpty("ssh-pass", fSshPass)
	mustBeNotEmpty("cert-user", fCertUser)
	mustBeNotEmpty("cert-email", fCertEmail)

	nodes := strings.Split(fHosts, ",")

	now := time.Now()
	priv, rootCert := handleRootCert(now)
	handleNodeCerts(nodes, now, priv, rootCert, fHttpUser, fHttpPass, fSshUser, fSshPass)
	handleClientCert(now, priv, rootCert, fCertUser, fCertEmail)

	err := cbcerthelper.EnableClientCertAuth(fHttpUser, fHttpPass, nodes[0])
	if err != nil {
		log.Fatal(err)
	}
}

func handleRootCert(now time.Time) (*rsa.PrivateKey, *x509.Certificate) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	rootCert, rootCertBytes, err := cbcerthelper.CreateRootCert(now, now.Add(3650*24*time.Hour), priv)
	if err != nil {
		log.Fatalf("Failed to generate root cert: %v", err)
	}

	err = cbcerthelper.WriteLocalCert("ca.pem", cbcerthelper.CertTypeCertificate, rootCertBytes)
	if err != nil {
		log.Fatal(err)
	}

	err = cbcerthelper.WriteLocalKey("ca.key", priv)
	if err != nil {
		log.Fatal(err)
	}

	return priv, rootCert
}

func handleNodeCerts(nodes []string, now time.Time, priv *rsa.PrivateKey, rootCert *x509.Certificate, httpUser, httpPass,
	sshUser, sshPass string) {
	for _, host := range nodes {
		nodePrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("Failed to generate private key: %v", err)
		}

		nodeCSR, nodeCSRBytes, err := cbcerthelper.CreateNodeCertReq(nodePrivKey)
		if err != nil {
			log.Fatalf("Failed to create certificate request: %v", err)
		}

		_, nodeCertBytes, err := cbcerthelper.CreateNodeCert(now, now.Add(365*24*time.Hour), priv, host, rootCert, nodeCSR)
		if err != nil {
			log.Fatalf("Failed to create node certificate: %v", err)
		}

		err = cbcerthelper.WriteLocalCert(fmt.Sprintf("%s.csr", host), cbcerthelper.CertTypeCertificateRequest, nodeCSRBytes)
		if err != nil {
			log.Fatal(err)
		}

		err = cbcerthelper.WriteLocalCert(fmt.Sprintf("%s.chain.pem", host), cbcerthelper.CertTypeCertificate, nodeCertBytes)
		if err != nil {
			log.Fatal(err)
		}

		err = cbcerthelper.WriteLocalKey(fmt.Sprintf("%s.pkey.key", host), nodePrivKey)
		if err != nil {
			log.Fatal(err)
		}

		func() {
			client, err := dial(sshUser, sshPass, host)
			if err != nil {
				log.Fatalf("Failed to connect to node: %v", err)
			}

			sftpCli, err := sftp.NewClient(client)
			if err != nil {
				log.Fatal(err)
			}
			defer func() {
				if err := sftpCli.Close(); err != nil {
					log.Println("Failed to close sftp client")
				}
			}()

			err = sftpCli.Mkdir("/opt/couchbase/var/lib/couchbase/inbox")
			if err != nil {
				log.Printf("Failed to create inbox: %v\n", err)
			}

			err = cbcerthelper.WriteRemoteCert("/opt/couchbase/var/lib/couchbase/inbox/chain.pem", "CERTIFICATE",
				nodeCertBytes, sftpCli)
			if err != nil {
				log.Fatal(err)
			}

			err = cbcerthelper.WriteRemoteKey("/opt/couchbase/var/lib/couchbase/inbox/pkey.key", nodePrivKey, sftpCli)
			if err != nil {
				log.Fatal(err)
			}
		}()

		err = cbcerthelper.UploadClusterCA(rootCert.Raw, httpUser, httpPass, host)
		if err != nil {
			log.Fatal(err)
		}

		err = cbcerthelper.ReloadClusterCert(httpUser, httpPass, host)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func handleClientCert(now time.Time, caPrivateKey *rsa.PrivateKey, caCert *x509.Certificate, certUser, certEmail string) {
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	clientCSR, clientCSRBytes, err := cbcerthelper.CreateClientCertReq(certUser, clientKey)
	if err != nil {
		log.Fatalf("Failed to create client cert request: %v", err)
	}

	_, clientCertBytes, err := cbcerthelper.CreateClientCert(now, now.Add(365*24*time.Hour), caPrivateKey, caCert,
		clientCSR, certEmail)
	if err != nil {
		log.Fatalf("Failed to create client cert: %v", err)
	}

	err = cbcerthelper.WriteLocalCert("client.csr", cbcerthelper.CertTypeCertificateRequest, clientCSRBytes)
	if err != nil {
		log.Fatal(err)
	}

	err = cbcerthelper.WriteLocalCert("client.pem", cbcerthelper.CertTypeCertificate, clientCertBytes)
	if err != nil {
		log.Fatal(err)
	}

	err = cbcerthelper.WriteLocalKey("client.key", clientKey)
	if err != nil {
		log.Fatal(err)
	}
}

func dial(username, password, host string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial connection")
	}

	return conn, nil
}
