package webhook

// The core's events come from the audit log. Every membership change is
// already recorded there, by whichever service made it (user for joins,
// leaves and status, authorization for roles), in the same call that fails
// the action if it cannot be recorded. So the audit service is the one
// place that sees all of them, and it forwards the ones below to the
// webhooks service once each entry is written. The audit entry's id is the
// message id, so a forward that is retried is still one event.

// AuditEntry is the part of an audit entry FromAudit reads.
type AuditEntry struct {
	Action   string
	TargetID string
	Actor    string
	Details  map[string]any
}

// FromAudit is the webhook event an audit entry is, if it is one: its type
// and its data, built from ids and values only, never copied wholesale.
func FromAudit(e AuditEntry) (Type, map[string]any, bool) {
	str := func(k string) (string, bool) {
		s, ok := e.Details[k].(string)
		return s, ok && s != ""
	}
	data := map[string]any{"membership_id": e.TargetID, "actor": e.Actor}
	copyID := func(keys ...string) {
		for _, k := range keys {
			if v, ok := str(k); ok {
				data[k] = v
			}
		}
	}
	switch e.Action {
	case "membership.created":
		copyID("user_id", "role", "source")
		return MemberAdded, data, true
	case "membership.status_changed":
		from, _ := str("from")
		to, _ := str("to")
		copyID("user_id")
		switch {
		case to == "active" && from != "active":
			data["reason"] = "reactivated"
			return MemberAdded, data, true
		case from == "active" && to != "active" && to != "":
			data["reason"] = to
			return MemberRemoved, data, true
		}
	case "membership.left":
		copyID("user_id")
		data["reason"] = "left"
		return MemberRemoved, data, true
	case "account.deleted":
		copyID("user_id")
		data["reason"] = "account_deleted"
		return MemberRemoved, data, true
	case "role.changed":
		copyID("from", "to")
		return MemberRoleChanged, data, true
	}
	return "", nil, false
}
