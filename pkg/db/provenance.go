package db

import (
	"context"
	"errors"
	"strings"
)

// Actor is who is making a change, recorded in created_by and
// last_modified_by. It is an identifier, never a name or an email:
//
//	membership:<uuid>   a person acting in an org
//	user:<uuid>         a person acting outside any org (sign-in, profile)
//	system:<service>    the platform itself, such as a housekeeping tick
type Actor string

// SystemActor is the platform acting on its own, named by service.
func SystemActor(service string) Actor { return Actor("system:" + service) }

// MembershipActor is a person acting inside an organization.
func MembershipActor(membershipID string) Actor { return Actor("membership:" + membershipID) }

// UserActor is a person acting outside any organization.
func UserActor(userID string) Actor { return Actor("user:" + userID) }

func (a Actor) valid() bool {
	kind, id, ok := strings.Cut(string(a), ":")
	if !ok || id == "" {
		return false
	}
	switch kind {
	case "membership", "user", "system":
		return true
	}
	return false
}

// ErrNoActor means a write was attempted without anyone to attribute it to.
// The auth middleware puts the caller in the context; background work
// names itself with SystemActor.
var ErrNoActor = errors.New("db: no actor in context; every write is attributed")

type actorKey struct{}

// WithActor returns a context whose writes are attributed to actor.
func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFrom is the actor in ctx, if any.
func ActorFrom(ctx context.Context) (Actor, bool) {
	actor, ok := ctx.Value(actorKey{}).(Actor)
	return actor, ok && actor.valid()
}

// provenanceFunction is installed in every service schema by Bootstrap and
// attached to every table as a BEFORE INSERT OR UPDATE trigger. The database,
// not the caller, fills the provenance columns: whatever a query sends for
// them is overwritten, so they cannot be set by hand.
//
// It also refuses to move a row to another org, since org_id is the sharding
// key and a row that changes org would change shard.
const provenanceFunction = `
CREATE OR REPLACE FUNCTION %[1]s.set_provenance() RETURNS trigger
LANGUAGE plpgsql AS $fn$
DECLARE
	actor text := current_setting('app.actor', true);
BEGIN
	IF actor IS NULL OR actor = '' THEN
		RAISE EXCEPTION 'no actor for write to %%.%%: write through pkg/db', TG_TABLE_SCHEMA, TG_TABLE_NAME
			USING ERRCODE = 'insufficient_privilege';
	END IF;
	IF TG_OP = 'INSERT' THEN
		NEW.created_by := actor;
		NEW.created_at := now();
	ELSE
		NEW.created_by := OLD.created_by;
		NEW.created_at := OLD.created_at;
		IF to_jsonb(NEW) ? 'org_id' AND to_jsonb(NEW)->'org_id' IS DISTINCT FROM to_jsonb(OLD)->'org_id' THEN
			RAISE EXCEPTION 'org_id of %%.%% cannot change', TG_TABLE_SCHEMA, TG_TABLE_NAME
				USING ERRCODE = 'check_violation';
		END IF;
	END IF;
	NEW.last_modified_by := actor;
	NEW.last_modified_at := now();
	RETURN NEW;
END
$fn$`
