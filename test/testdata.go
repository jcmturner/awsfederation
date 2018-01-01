package test

const (
	VaultRoot               = "/secret/"
	DBConnStr               = "${username}:${password}@tcp(127.0.0.1:3306)/awsfederation"
	DBCredsPath             = "dbcreds"
	IAMUserArnTemplate      = "arn:aws:iam::%s:user/%s"
	AWSAccountID1           = "012345678912"
	AWSAccountID2           = "234567890112"
	FedUserName1            = "TestFedUser1"
	FedUserName2            = "TestFedUser2"
	FedUserArn1             = "arn:aws:iam::012345678912:user/TestFedUser1"
	FedUserArn2             = "arn:aws:iam::234567890112:user/TestFedUser2"
	FedUserTTL1             = 30
	FedUserTTL2             = 60
	IAMUser1SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	IAMUser1SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	IAMUser1Expiration      = "2016-03-15T00:05:07Z"
	IAMUser1AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"
	IAMUser1MFASerial       = "arn:aws:iam::012345678912:mfa/test1"
	IAMUser1MFASecret       = "WKV7L1CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"
	IAMUser2SecretAccessKey = "9dje5ucXLB89EXAMPLELB8923FB892xMFI"
	IAMUser2SessionToken    = "BQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	IAMUser2Expiration      = "2017-08-15T03:05:07Z"
	IAMUser2AccessKeyId     = "ASIAJEXAMPLEXEG2JICEB"
	IAMUser2MFASerial       = "arn:aws:iam::223456789012:mfa/test2"
	IAMUser2MFASecret       = "V2NFI2CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"
	GenericResponseTmpl     = "{\"Message\":\"%s\",\"HTTPCode\":%d,\"ApplicationCode\":%d}"
	CreatedResponseTmpl     = "{\"CreatedEntity\":\"%s\",\"Message\":\"%s\",\"HTTPCode\":201,\"ApplicationCode\":0}"
	AccountClassName1       = "accountClass1"
	AccountClassID1         = 1
	AccountClassName2       = "accountClass2"
	AccountClassID2         = 2
	AccountTypeName1        = "accountType1"
	AccountTypeID1          = 1
	AccountTypeName2        = "accountType2"
	AccountTypeID2          = 2
	AccountStatusName1      = "accountStatus1"
	AccountStatusID1        = 1
	AccountStatusName2      = "accountStatus2"
	AccountStatusID2        = 2
	RoleARN1                = "arn:aws:iam::012345678912:role/rolename1"
	RoleARN2                = "arn:aws:iam::234567890112:role/rolename2"
	AuthzAttrib1            = "myGroup1"
	AuthzAttrib2            = "myGroup2"
	UUID1                   = "6901e2f6-0677-4a0c-95f8-174testuuid1"
	UUID2                   = "e1932ce8-212e-4cb1-b71c-906testuuid2"
)
