package appcode

const (
	Info                     = 0
	BadData                  = 1
	InvalidAuthentication    = 2
	Unauthorized             = 3
	AuthenticationError      = 4
	ServerConfigurationError = 5

	AssumeRoleError = 10

	FederationUserError         = 20
	FederationUserUnknown       = 21
	FederationUserAlreadyExists = 22
)
