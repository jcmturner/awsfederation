package assumerole

import (
	"encoding/json"
	"errors"
	"fmt"
	awssts "github.com/aws/aws-sdk-go/service/sts"
	"github.com/hashicorp/go-uuid"
	"github.com/jcmturner/awsfederation/apperrors"
	"github.com/jcmturner/awsfederation/config"
	"github.com/jcmturner/awsfederation/database"
	"github.com/jcmturner/awsfederation/federationuser"
	"github.com/jcmturner/awsfederation/sts"
	"github.com/jcmturner/goidentity"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type AuditDetail struct {
	Successful      bool
	RoleMappingID   string
	RoleArn         string
	RoleSessionName string
	SessionDuration time.Duration
	FederationUser  string
	Comment         string
}

func auditLog(l config.AuditLogLine, d AuditDetail, c *config.Config) {
	b, _ := json.Marshal(d)
	l.Detail = url.QueryEscape(string(b))
	c.AccessLog(l)
}

func Federate(u goidentity.Identity, id string, stmtMap database.StmtMap, fc *federationuser.FedUserCache, c *config.Config) (o *awssts.AssumeRoleOutput, err error) {
	eventUUID, err := uuid.GenerateUUID()
	if err != nil {
		return
	}
	auditLine := config.AuditLogLine{
		Username:   u.UserName(),
		UserDomain: u.Domain(),
		EventType:  "AssumeRoleFederation",
		Time:       time.Now().UTC(),
		UUID:       eventUUID,
	}
	d := AuditDetail{
		RoleMappingID:   id,
		RoleSessionName: "NA",
		SessionDuration: time.Duration(0),
		FederationUser:  "NA",
	}

	var authzed bool
	authzed, err = Authorize(u, id, stmtMap)
	if err != nil {
		d.Comment = fmt.Sprintf("Authorization check failed due to error: [%v]", err)
		c.ApplicationLogf("%v Request: %+v Details: %+v", err, auditLine, d)
		auditLog(auditLine, d, c)
		return
	}
	if authzed {
		role, fu, duration, policy, roleSessionNameFmt, e := RoleMappingLookup(id, stmtMap)
		if e != nil {
			err = fmt.Errorf("Error getting role mapping details during federation: [%v]", e)
			d.Comment = err.Error()
			c.ApplicationLogf("%v Request: %+v Details: %+v", err, auditLine, d)
			auditLog(auditLine, d, c)
			return
		}
		d.RoleArn = role
		d.FederationUser = fu
		o, err = sts.Federate(c, fc, fu, role, roleSessionNamef(roleSessionNameFmt, u), policy, duration)
		if err != nil {
			err = fmt.Errorf("Error performing federation: [%v]", err)
			d.RoleSessionName = o.AssumedRoleUser.String()
			d.SessionDuration = time.Duration(duration)
			d.Comment = err.Error()
			c.ApplicationLogf("%v Request: %+v Details: %+v", err, auditLine, d)
			auditLog(auditLine, d, c)
			return
		}
		return
	} else {
		d.Comment = "Access denied, user not authorized"
		err = apperrors.ErrUnauthorized{}.Errorf(d.Comment)
		auditLog(auditLine, d, c)
		return
	}
}

func Authorize(u goidentity.Identity, id string, stmtMap database.StmtMap) (bool, error) {
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

func RoleMappingLookup(id string, stmtMap database.StmtMap) (role string, fuStr string, duration int64, policyStr string, roleSessionNameFmt string, err error) {
	// Validate id format. Ensure no SQL injection.
	if _, err = uuid.ParseUUID(id); err != nil {
		return
	}
	if stmt, ok := stmtMap[database.StmtKeyRoleMappingLookup]; ok {
		err := stmt.QueryRow(id).Scan(&role, &fuStr, &duration, &policyStr, &roleSessionNameFmt)
		if err != nil {
			return role, fuStr, duration, policyStr, roleSessionNameFmt, err
		}
		return role, fuStr, duration, policyStr, roleSessionNameFmt, nil
	}
	return role, fuStr, duration, policyStr, roleSessionNameFmt, errors.New("Prepared statement for DB role mapping lookup check not found")
}

func roleSessionNamef(format string, u goidentity.Identity) string {
	format = strings.Replace(format, "${username}", u.UserName(), -1)
	format = strings.Replace(format, "${displayname}", u.DisplayName(), -1)
	format = strings.Replace(format, "${domain}", u.Domain(), -1)
	format = strings.Replace(format, "${human}", strconv.FormatBool(u.Human()), -1)
	return format
}
