package ldapauth

import (
	"errors"
	"strings"

	"github.com/go-ldap/ldap"
)

var (
	errLDAPConnection         = errors.New("ldap connection error")
	errLDAPInvalidCredentials = errors.New("invalid credentials")
	errLDAPUserNotFound       = errors.New("user not found")
	errLDAPUndefined          = errors.New("undefined error")
)

type LdapUser struct {
	Name        string
	Department  string
	Email       string
	Description string
}

type ldapAuthenticator struct {
	BaseDN   string
	FilterDN string
	Address  string
}

func NewLdapAuthenticator(addres, baseDN, filterDN string) Authenticator {
	return &ldapAuthenticator{
		BaseDN:   baseDN,
		FilterDN: filterDN,
		Address:  addres,
	}
}

func (l *ldapAuthenticator) Auth(login, password string) (LdapUser, error) {
	conn, err := ldap.Dial("tcp", l.Address)
	if err != nil {
		return LdapUser{}, errLDAPConnection
	}
	defer conn.Close()
	err = conn.Bind(login, password)
	if err != nil {
		return LdapUser{}, errLDAPInvalidCredentials
	}

	res, err := conn.Search(
		ldap.NewSearchRequest(
			l.BaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			l.filter(login),
			[]string{"sAMAccountName", "cn", "givenName", "mail", "department", "description"},
			nil,
		))
	if err != nil || len(res.Entries) != 1 {
		return LdapUser{}, errLDAPUserNotFound
	}

	for _, entry := range res.Entries {
		return LdapUser{
			Name:        entry.GetAttributeValue("cn"),
			Email:       entry.GetAttributeValue("mail"),
			Department:  entry.GetAttributeValue("department"),
			Description: entry.GetAttributeValue("description"),
		}, nil
	}
	return LdapUser{}, errLDAPUndefined
}

func (l *ldapAuthenticator) filter(needle string) string {
	res := strings.ReplaceAll(
		l.FilterDN,
		"{username}",
		needle,
	)
	return res
}
