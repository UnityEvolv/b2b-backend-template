package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
)

// The first platform operator. Inviting into the platform org needs an
// operator, so a fresh deployment has nobody who could invite the first one.
// BOOTSTRAP_OPERATOR_EMAIL names that person: on start, while the platform
// org has no active member and no open invite, this service invites the
// address as the platform's Owner, through the same invite, email and audit
// path as any other. Once somebody has accepted, or while the invite is
// still open, a start does nothing; if the invite lapses unaccepted, the
// next start sends a fresh one. The operator then signs in with a password
// and, because the platform org always demands it, a second factor.

// platformName is what emails sent on the platform org's behalf call it.
// The platform org has no record in the organization service to ask.
const platformName = "unityofis"

// orgName is the org's name for an email on its behalf.
func (s *Server) orgName(ctx context.Context, orgID uuid.UUID) (string, error) {
	if strings.EqualFold(orgID.String(), auth.PlatformOrg) {
		return platformName, nil
	}
	return s.orgs.Name(ctx, orgID)
}

// BootstrapOperator invites address as the platform's first operator unless
// the platform org already has an active member or an open invite. Reports
// whether an invite was sent. An empty or malformed address does nothing;
// the caller logs no address either way.
func (s *Server) BootstrapOperator(ctx context.Context, address string) (bool, error) {
	address = normalizeEmail(address)
	if address == "" {
		return false, nil
	}
	platform := uuid.MustParse(auth.PlatformOrg)
	// Members live in the user service's schema: asked, never read.
	active, err := s.users.CountMembers(ctx, platform)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	if active > 0 {
		return false, nil
	}
	_, refused, err := s.issue(system(ctx), platform, inviteRequest{
		email: address, kind: kindMember, role: string(authz.Owner), app: "platform", ttl: defaultInviteTTL, firstOnly: true,
	})
	if err != nil {
		return false, withoutURL(err)
	}
	return refused == "", nil
}

// withoutURL is err with any request URL dropped: looking the address up
// puts it in a query string, and the caller logs the error.
func withoutURL(err error) error {
	var u *url.Error
	if errors.As(err, &u) {
		return fmt.Errorf("%s request: %w", u.Op, u.Err)
	}
	return err
}
