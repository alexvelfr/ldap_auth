package ldapauth

type Authenticator interface {
	Auth(login, password string) (LdapUser, error)
}
