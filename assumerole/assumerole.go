package assumerole

import (
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/goidentity"
	"errors"
	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/config"
	"fmt"
	"strings"
	"strconv"
	"time"
	"github.com/jcmturner/awsfederation/sts"
	awssts "github.com/aws/aws-sdk-go/service/sts"
	"encoding/json"
	"net/url"
)

type AuditDetail struct {
	Successful bool
	RoleMappingID string
	RoleArn string
	RoleSessionName string
	SessionDuration time.Duration
	FederationUser string
	Comment string
}

func auditLog(l config.AuditLogLine, d AuditDetail, c *config.Config) {
	b, _ := json.Marshal(d)
	l.Detail = url.QueryEscape(string(b))
	c.AccessLog(l)
}

func Federate(u goidentity.Identity, id string, stmtMap *database.StmtMap, fc *federationuser.FedUserCache, c config.Config) (*awssts.AssumeRoleOutput, error) {
	auditLine := config.AuditLogLine{
		Username: u.UserName(),
		UserRealm: u.Domain(),
		EventType: "AssumeRoleFederation",
		Time: time.Now().UTC(),
	}

	if ok, err := Authorize(u, id, stmtMap); ok {
		role, fu, duration, policy, roleSessionNameFmt, err := RoleMappingLookup(id, stmtMap)
		if err != nil {
			d := AuditDetail{
				Successful: false,
				RoleMappingID: id,
				RoleArn: role,
				RoleSessionName: "NA",
				SessionDuration: time.Duration(0),
				FederationUser: fu,
				Comment: fmt.Sprintf("Error getting role mapping details: %v", err),
			}
			auditLog(auditLine, d, c)
			return awssts.AssumeRoleOutput{}, fmt.Errorf("Error getting role mapping details: %v", err)
		}
		o, err := sts.Federate(c, fc, fu, role, roleSessionNamef(roleSessionNameFmt, u), policy, duration)
		if err != nil {
			d := AuditDetail{
				Successful: false,
				RoleMappingID: id,
				RoleArn: role,
				RoleSessionName: o.AssumedRoleUser.String(),
				SessionDuration: time.Duration(duration),
				FederationUser: fu,
				Comment: fmt.Sprintf("Error performing federation: %v", err),
			}
			auditLog(auditLine, d, c)
			return o, fmt.Errorf("Error performing federation: %v", err)
		}
		return o, nil
	} else if err != nil {
		d := AuditDetail{
			Successful: false,
			RoleMappingID: id,
			RoleSessionName: "NA",
			SessionDuration: time.Duration(0),
			FederationUser: fu,
			Comment: fmt.Sprintf("Error getting role mapping details: %v", err),
		}
		auditLog(auditLine, d, c)
		return awssts.AssumeRoleOutput{}, err
	} else {

	}

}

func Authorize(u goidentity.Identity, id string, stmtMap *database.StmtMap) (bool, error) {
	// Validate id format. Ensure no SQL injection.
	if _, err := uuid.ParseUUID(id); err != nil {
		return false, errors.New("Role mapping ID not valid")
	}
	if stmt, ok := stmtMap[database.StmtKeyAuthzCheck]; ok {
		rows, err := stmt.Query(id)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var a string
		for rows.Next() {
			err := rows.Scan(&a)
			if err != nil {
				return false, err
			}
			if u.Authorized(a) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errors.New("Prepared statement for DB authorization check not found")
}

func RoleMappingLookup(id string, stmtMap *database.StmtMap) (string, string, int, string, string, error) {
	// Validate id format. Ensure no SQL injection.
	if _, err := uuid.ParseUUID(id); err != nil {
		return false, errors.New("Role mapping ID not valid")
	}
	var (
		role string
		fuStr string
		durationInt int64
		policyStr string
		roleSessionNameFmt string
	)
	if stmt, ok := stmtMap[database.StmtKeyRoleMappingLookup]; ok {
		err := stmt.QueryRow(id).Scan(&role, &fuStr, &durationInt, &policyStr, &roleSessionNameFmt)
		if err != nil {
			return role, fuStr, durationInt, policyStr, roleSessionNameFmt, err
		}
		return role, fuStr, durationInt, policyStr, roleSessionNameFmt, nil
	}
	return role, fuStr, durationInt, policyStr, roleSessionNameFmt, errors.New("Prepared statement for DB role mapping lookup check not found")
}

func roleSessionNamef (format string, u goidentity.Identity) string {
	format = strings.Replace(format, "${username}", u.UserName(), -1)
	format = strings.Replace(format, "${displayname}", u.DisplayName(), -1)
	format = strings.Replace(format, "${domain}", u.Domain(), -1)
	format = strings.Replace(format, "${human}", strconv.FormatBool(u.Human()), -1)
	return format
}