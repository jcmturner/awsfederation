package test

import (
	"database/sql"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/gotestingtools/testingTLS"
	"github.com/jcmturner/vaultmock"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEnv(t *testing.T) (*config.Config, *sql.DB, sqlmock.Sqlmock, map[int]*sqlmock.ExpectedPrepare, *database.StmtMap, *httptest.Server) {
	// Database mock and prepare statements
	db, mock, ep, stmtMap := database.Mock(t)

	// Start a mock vault process
	s, addr, _, cert, appID, userID := vaultmock.RunMockVault(t)
	vCertFile := testingTLS.WriteCertToFile(t, cert)
	defer os.Remove(vCertFile.Name())

	// Create a cert for the server
	certPath, keyPath, _, _ := testingTLS.GenerateSelfSignedTLSKeyPairFiles(t)
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	c, _ := config.Mock()
	c.SetTLS(
		config.TLS{
			Enabled:         true,
			CertificateFile: certPath,
			KeyFile:         keyPath,
		})
	c.SetVault(addr, vCertFile.Name(), appID, userID, c.Vault.Config.SecretsPath)
	return c, db, mock, ep, stmtMap, s
}
