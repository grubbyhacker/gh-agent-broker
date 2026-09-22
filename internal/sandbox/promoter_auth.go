package sandbox

import (
	"errors"
	"net/http"
)

// VerifiedPromoter is the authenticated identity presented to release
// authorization and audit handling. It deliberately carries no credential.
type VerifiedPromoter struct {
	Name      string
	Principal OperatorPrincipal
}

// PromoterAuthenticator verifies who made a release-registry request. Release
// handlers authorize the resulting identity separately, so replacing bearer
// token verification with an OIDC verifier only changes an implementation of
// this interface, not registry operations or their audit records.
type PromoterAuthenticator interface {
	AuthenticatePromoter(*http.Request) (VerifiedPromoter, error)
}

var errUnauthorizedPromoter = errors.New("unauthorized")

type tokenPromoterAuthenticator struct {
	principals map[string]OperatorPrincipal
}

func (a tokenPromoterAuthenticator) AuthenticatePromoter(r *http.Request) (VerifiedPromoter, error) {
	token := bearerToken(r)
	for name, principal := range a.principals {
		if secureTokenEqual(token, principal.Token) {
			return VerifiedPromoter{Name: name, Principal: principal}, nil
		}
	}
	return VerifiedPromoter{}, errUnauthorizedPromoter
}
