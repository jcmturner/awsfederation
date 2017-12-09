package appcodes

const (
	Info                     = 0
	BadData                  = 1
	InvalidAuthentication    = 2
	Unauthorized             = 3
	AuthenticationError      = 4
	ServerConfigurationError = 5
	DatabaseError            = 6

	AssumeRoleError = 10

	FederationUserError         = 20
	FederationUserUnknown       = 21
	FederationUserAlreadyExists = 22

	AccountClassUnknown       = 21
	AccountClassAlreadyExists = 22
)
