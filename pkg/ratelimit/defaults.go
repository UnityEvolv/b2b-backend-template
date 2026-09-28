package ratelimit

import "time"

// The limits every known consumer starts from. A story that adds one of these
// endpoints binds it to the rule here rather than inventing its own number;
// changing a number is a change to this file, reviewed in one place.
var (
	// Every request to a service, per client address, counted in front of
	// authentication so token guessing is slowed too. Generous, because a whole
	// office can share one address.
	PerAddress = Rule{Name: "address", Limit: 1200, Window: time.Minute}

	// Endpoints reachable without a token (sign-up, invite lookup), per client
	// address, on top of PerAddress.
	Unauthenticated = Rule{Name: "unauthenticated", Limit: 60, Window: time.Minute}

	// Ordinary authenticated reads and writes, per membership.
	AuthenticatedRead  = Rule{Name: "read", Limit: 600, Window: time.Minute}
	AuthenticatedWrite = Rule{Name: "write", Limit: 120, Window: time.Minute}

	// Failed sign-ins, per account and per address, counted with
	// Check/Penalize so only failures spend. Fails closed.
	FailedSignIn = Rule{Name: "signin-failed", Limit: 10, Window: 15 * time.Minute, FailClosed: true}
	// Password reset requests, per account. Fails closed.
	PasswordReset = Rule{Name: "password-reset", Limit: 3, Window: time.Hour, FailClosed: true}

	// Invites sent, per membership.
	InviteSend = Rule{Name: "invite-send", Limit: 50, Window: time.Hour}
	// Knocks, per membership. The engine also limits knocks per room.
	Knock = Rule{Name: "knock", Limit: 20, Window: time.Minute}

	// Chat is the easiest thing to flood, so these are per membership and tight:
	// a stuck key or a script is throttled without the room noticing.
	MessageSend    = Rule{Name: "message-send", Limit: 10, Window: 10 * time.Second}
	TypingEvent    = Rule{Name: "typing", Limit: 20, Window: 10 * time.Second}
	MentionFanOut  = Rule{Name: "mention-fanout", Limit: 30, Window: time.Minute}
	AttachmentSend = Rule{Name: "attachment", Limit: 20, Window: time.Minute}

	// An identity provider pushing users and groups over SCIM, per org. A
	// full sync is thousands of requests and providers retry hard, so this is
	// generous; it is there to stop one org starving the service.
	SCIM = Rule{Name: "scim", Limit: 2400, Window: time.Minute}

	// Incoming provider webhooks, per org.
	ProviderWebhook = Rule{Name: "provider-webhook", Limit: 3000, Window: time.Minute}
)
