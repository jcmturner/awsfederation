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
	IAMUser1SecretAccessKey = "9drTJvcXLB89EXAMPLELB8923FB892xMFI"
	IAMUser1SessionToken    = "AQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	IAMUser1Expiration      = "2016-03-15T00:05:07Z"
	IAMUser1AccessKeyId     = "ASIAJEXAMPLEXEG2JICEA"
	IAMUser2SecretAccessKey = "9dje5ucXLB89EXAMPLELB8923FB892xMFI"
	IAMUser2SessionToken    = "BQoXdzELDDY//////////wEaoAK1wvxJY12r2IrDFT2IvAzTCn3zHoZ7YNtpiQLF0MqZye/qwjzP2iEXAMPLEbw/m3hsj8VBTkPORGvr9jM5sgP+w9IZWZnU+LWhmg+a5fDi2oTGUYcdg9uexQ4mtCHIHfi4citgqZTgco40Yqr4lIlo4V2b2Dyauk0eYFNebHtYlFVgAUj+7Indz3LU0aTWk1WKIjHmmMCIoTkyYp/k7kUG7moeEYKSitwQIi6Gjn+nyzM+PtoA3685ixzv0R7i5rjQi0YE0lf1oeie3bDiNHncmzosRM6SFiPzSvp6h/32xQuZsjcypmwsPSDtTPYcs0+YN/8BRi2/IcrxSpnWEXAMPLEXSDFTAQAM6Dl9zR0tXoybnlrZIwMLlMi1Kcgo5OytwU="
	IAMUser2Expiration      = "2017-08-15T03:05:07Z"
	IAMUser2AccessKeyId     = "ASIAJEXAMPLEXEG2JICEB"
	IAMUser2MFASerial       = "arn:aws:iam::223456789012:mfa/test2"
	IAMUser2MFASecret       = "V2NFI2CRKFCMZJD232ONV5OLVPN5H3ZO2553QHFPXJK4BJN4X3JBYEQ6DJSBXE7H"
)
