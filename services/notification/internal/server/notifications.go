package server

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/notify"
	"github.com/UnityEvolv/b2b-backend-template/services/notification/internal/store"
)

// Notifications is what the notification endpoints need beyond the outbox.
type Notifications struct {
	Router *notify.Router
	Authz  authz.Checker
	// VAPIDPublic is the web push key browsers subscribe with; empty turns
	// web push off.
	VAPIDPublic string
	// LinkKey signs one-click unsubscribe links.
	LinkKey []byte
}

// WithNotifications is s, answering the feed, preferences and devices.
func (s *Server) WithNotifications(n Notifications) *Server {
	s.n = &n
	return s
}

func forbidden(message string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: message}
}

func invalid(message string, fields map[string]string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeInvalidRequest, Message: message, Fields: &fields}
}

// member is the caller's membership in org, or an error when they have none
// there.
func (s *Server) member(ctx context.Context, org uuid.UUID) (uuid.UUID, auth.Caller, error) {
	if s.n == nil {
		return uuid.Nil, auth.Caller{}, auth.ErrForbidden
	}
	if err := auth.RequireOrg(ctx, org.String()); err != nil {
		return uuid.Nil, auth.Caller{}, err
	}
	c, _ := auth.CallerFrom(ctx)
	id, err := uuid.Parse(c.MembershipID)
	if c.IsService() || err != nil {
		return uuid.Nil, c, auth.ErrForbidden
	}
	return id, c, nil
}

func toEntry(e store.FeedEntry) api.FeedEntry {
	out := api.FeedEntry{Id: e.ID, Category: api.Category(e.Category), Kind: e.Kind, Link: e.Link, Count: int(e.Count), OccurredAt: e.OccurredAt, Read: e.ReadAt.Valid}
	_ = json.Unmarshal(e.Data, &out.Data)
	_ = json.Unmarshal(e.Items, &out.Items)
	if out.Data == nil {
		out.Data = map[string]any{}
	}
	if out.Items == nil {
		out.Items = []map[string]any{}
	}
	return out
}

// ListNotifications is the caller's feed, newest first.
func (s *Server) ListNotifications(ctx context.Context, req api.ListNotificationsRequestObject) (api.ListNotificationsResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.ListNotifications403JSONResponse(forbidden("Not permitted for this organization.")), nil
	}
	limit := httpx.PageSize(req.Params.Limit, 30, 100)
	var cursor httpx.Cursor
	if req.Params.Cursor != nil {
		c, _, err := httpx.DecodeCursor(*req.Params.Cursor)
		if err != nil {
			return api.ListNotifications400JSONResponse{ErrorJSONResponse: invalid("The cursor is not valid.", map[string]string{"cursor": "not a cursor this list issued"})}, nil
		}
		cursor = c
	}
	var category pgtype.Text
	if req.Params.Category != nil {
		category = pgtype.Text{String: string(*req.Params.Category), Valid: true}
	}
	var (
		rows   []store.FeedEntry
		unread int32
	)
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if rows, err = q.ListFeed(ctx, store.ListFeedParams{
			OrgID: req.OrgId, MembershipID: me, Category: category, PageSize: int32(limit + 1),
			BeforeAt: pgtype.Timestamptz{Time: cursor.At, Valid: !cursor.At.IsZero()}, BeforeID: pgtype.UUID{Bytes: cursor.ID, Valid: !cursor.At.IsZero()},
		}); err != nil {
			return err
		}
		unread, err = q.CountUnread(ctx, store.CountUnreadParams{OrgID: req.OrgId, MembershipID: me})
		return err
	})
	if err != nil {
		return nil, err
	}
	page := api.ListNotifications200JSONResponse{Entries: make([]api.FeedEntry, 0, len(rows)), Unread: int(unread)}
	for i, r := range rows {
		if i == limit {
			next := httpx.Cursor{At: rows[i-1].OccurredAt, ID: rows[i-1].ID}.Encode()
			page.NextCursor = &next
			break
		}
		page.Entries = append(page.Entries, toEntry(r))
	}
	return page, nil
}

// ReadNotifications marks entries read: some, all, or those about one thing
// the person just opened. Every open app is told, so the count clears
// everywhere at once.
func (s *Server) ReadNotifications(ctx context.Context, req api.ReadNotificationsRequestObject) (api.ReadNotificationsResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.ReadNotifications403JSONResponse{ErrorJSONResponse: forbidden("Not permitted for this organization.")}, nil
	}
	b := req.Body
	var unread int32
	var changed int64
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		switch {
		case b.About != nil && *b.About != "":
			changed, err = q.MarkFeedReadByLink(ctx, store.MarkFeedReadByLinkParams{OrgID: req.OrgId, MembershipID: me, GroupKey: pgtype.Text{String: *b.About, Valid: true}})
		case b.All != nil && *b.All:
			changed, err = q.MarkFeedRead(ctx, store.MarkFeedReadParams{OrgID: req.OrgId, MembershipID: me})
		case b.Ids != nil && len(*b.Ids) > 0:
			changed, err = q.MarkFeedRead(ctx, store.MarkFeedReadParams{OrgID: req.OrgId, MembershipID: me, Ids: *b.Ids})
		}
		if err != nil {
			return err
		}
		unread, err = q.CountUnread(ctx, store.CountUnreadParams{OrgID: req.OrgId, MembershipID: me})
		return err
	})
	if err != nil {
		return nil, err
	}
	if changed > 0 {
		s.n.Router.Live(ctx, req.OrgId, me)
	}
	return api.ReadNotifications200JSONResponse{Unread: int(unread)}, nil
}

func toPreferences(p store.Preference, org store.OrgSetting) api.NotificationPreferences {
	channels := map[string]api.ChannelChoice{}
	for c, ch := range notify.Resolve(p.Channels, org.Channels) {
		channels[string(c)] = api.ChannelChoice{InApp: ch.InApp, Push: ch.Push, Email: ch.Email}
	}
	days := make([]int, len(p.QuietDays))
	for i, d := range p.QuietDays {
		days[i] = int(d)
	}
	allowed := org.PreviewsAllowed
	out := api.NotificationPreferences{
		Channels: channels, PushPreviews: p.PushPreviews && allowed, PreviewsAllowed: &allowed, Muted: p.Muted,
		QuietHours: api.QuietHours{Enabled: p.QuietEnabled, StartMinute: int(p.QuietStartMinute), EndMinute: int(p.QuietEndMinute), Days: days},
	}
	if out.Muted == nil {
		out.Muted = []uuid.UUID{}
	}
	if p.DigestMinute.Valid {
		m := int(p.DigestMinute.Int32)
		out.DigestMinute = &m
	}
	return out
}

// defaults is a preferences row for someone who never saved one.
func defaults(org, me uuid.UUID) store.Preference {
	return store.Preference{OrgID: org, MembershipID: me, Channels: []byte("{}"), PushPreviews: true, QuietStartMinute: 22 * 60, QuietEndMinute: 7 * 60, QuietDays: []int16{1, 2, 3, 4, 5, 6, 7}, Muted: []uuid.UUID{}}
}

func (s *Server) readPreferences(ctx context.Context, org, me uuid.UUID) (store.Preference, store.OrgSetting, error) {
	var (
		p store.Preference
		o store.OrgSetting
	)
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		p, err = q.GetPreferences(ctx, store.GetPreferencesParams{OrgID: org, MembershipID: me})
		if errors.Is(err, pgx.ErrNoRows) {
			p, err = defaults(org, me), nil
		}
		if err != nil {
			return err
		}
		o, err = q.GetOrgSettings(ctx, org)
		if errors.Is(err, pgx.ErrNoRows) {
			o, err = store.OrgSetting{OrgID: org, Channels: []byte("{}"), PreviewsAllowed: true}, nil
		}
		return err
	})
	return p, o, err
}

// GetNotificationPreferences is the caller's preferences, defaults filled in.
func (s *Server) GetNotificationPreferences(ctx context.Context, req api.GetNotificationPreferencesRequestObject) (api.GetNotificationPreferencesResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.GetNotificationPreferences403JSONResponse{ErrorJSONResponse: forbidden("Not permitted for this organization.")}, nil
	}
	p, o, err := s.readPreferences(ctx, req.OrgId, me)
	if err != nil {
		return nil, err
	}
	return api.GetNotificationPreferences200JSONResponse(toPreferences(p, o)), nil
}

// channelsJSON is the stored form of a grid: known categories only.
func channelsJSON(in map[string]api.ChannelChoice) ([]byte, map[string]string) {
	out := map[notify.Category]notify.Channels{}
	for k, v := range in {
		c := notify.Category(k)
		if !c.Valid() {
			return nil, map[string]string{"channels." + k: "not a category"}
		}
		out[c] = notify.Channels{InApp: v.InApp, Push: v.Push, Email: v.Email}
	}
	raw, _ := json.Marshal(out)
	return raw, nil
}

// SetNotificationPreferences saves the caller's preferences; they apply to
// the next event, on every device.
func (s *Server) SetNotificationPreferences(ctx context.Context, req api.SetNotificationPreferencesRequestObject) (api.SetNotificationPreferencesResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.SetNotificationPreferences403JSONResponse(forbidden("Not permitted for this organization.")), nil
	}
	b := req.Body
	raw, fields := channelsJSON(b.Channels)
	q := b.QuietHours
	if fields == nil {
		fields = map[string]string{}
	}
	if q.StartMinute < 0 || q.StartMinute > 1439 || q.EndMinute < 0 || q.EndMinute > 1439 {
		fields["quiet_hours"] = "minutes between 0 and 1439"
	}
	days := make([]int16, 0, len(q.Days))
	for _, d := range q.Days {
		if d < 1 || d > 7 {
			fields["quiet_hours.days"] = "ISO weekdays, 1 to 7"
			break
		}
		if !slices.Contains(days, int16(d)) {
			days = append(days, int16(d))
		}
	}
	if b.DigestMinute != nil && (*b.DigestMinute < 0 || *b.DigestMinute > 1439) {
		fields["digest_minute"] = "minutes between 0 and 1439"
	}
	if len(b.Muted) > 500 {
		fields["muted"] = "at most 500"
	}
	if len(fields) > 0 {
		return api.SetNotificationPreferences400JSONResponse{ErrorJSONResponse: invalid("Some preferences are not valid.", fields)}, nil
	}
	digest := pgtype.Int4{}
	if b.DigestMinute != nil {
		digest = pgtype.Int4{Int32: int32(*b.DigestMinute), Valid: true}
	}
	muted := b.Muted
	if muted == nil {
		muted = []uuid.UUID{}
	}
	var (
		p store.Preference
		o store.OrgSetting
	)
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		st := store.New(tx)
		var err error
		if p, err = st.UpsertPreferences(ctx, store.UpsertPreferencesParams{
			OrgID: req.OrgId, MembershipID: me, Channels: raw, PushPreviews: b.PushPreviews, DigestMinute: digest,
			QuietEnabled: q.Enabled, QuietStartMinute: int32(q.StartMinute), QuietEndMinute: int32(q.EndMinute), QuietDays: days, Muted: muted,
		}); err != nil {
			return err
		}
		o, err = st.GetOrgSettings(ctx, req.OrgId)
		if errors.Is(err, pgx.ErrNoRows) {
			o, err = store.OrgSetting{OrgID: req.OrgId, Channels: []byte("{}"), PreviewsAllowed: true}, nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.SetNotificationPreferences200JSONResponse(toPreferences(p, o)), nil
}

// TestNotification sends one test on a channel to the caller.
func (s *Server) TestNotification(ctx context.Context, req api.TestNotificationRequestObject) (api.TestNotificationResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.TestNotification403JSONResponse(forbidden("Not permitted for this organization.")), nil
	}
	channel := string(req.Body.Channel)
	switch channel {
	case "in_app", "push", "email":
	default:
		return api.TestNotification400JSONResponse{ErrorJSONResponse: invalid("Choose a channel.", map[string]string{"channel": "in_app, push or email"})}, nil
	}
	n, err := s.n.Router.Test(ctx, req.OrgId, me, channel)
	if err != nil {
		return nil, err
	}
	return api.TestNotification202JSONResponse{Delivered: n}, nil
}

func (s *Server) orgSettings(ctx context.Context, org uuid.UUID) (store.OrgSetting, error) {
	var o store.OrgSetting
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		var err error
		o, err = store.New(tx).GetOrgSettings(ctx, org)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.OrgSetting{OrgID: org, Channels: []byte("{}"), PreviewsAllowed: true}, nil
	}
	return o, err
}

func toOrgSettings(o store.OrgSetting) api.OrgNotificationSettings {
	channels := map[string]api.ChannelChoice{}
	for c, ch := range notify.Resolve(nil, o.Channels) {
		channels[string(c)] = api.ChannelChoice{InApp: ch.InApp, Push: ch.Push, Email: ch.Email}
	}
	return api.OrgNotificationSettings{Channels: channels, PreviewsAllowed: o.PreviewsAllowed}
}

// GetOrgNotificationSettings is the org's defaults, for its people.
func (s *Server) GetOrgNotificationSettings(ctx context.Context, req api.GetOrgNotificationSettingsRequestObject) (api.GetOrgNotificationSettingsResponseObject, error) {
	if s.n == nil || auth.RequireOrgOrPlatform(ctx, req.OrgId.String()) != nil {
		return api.GetOrgNotificationSettings403JSONResponse{ErrorJSONResponse: forbidden("Not permitted for this organization.")}, nil
	}
	o, err := s.orgSettings(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetOrgNotificationSettings200JSONResponse(toOrgSettings(o)), nil
}

// SetOrgNotificationSettings changes the org's defaults: an Owner's call.
func (s *Server) SetOrgNotificationSettings(ctx context.Context, req api.SetOrgNotificationSettingsRequestObject) (api.SetOrgNotificationSettingsResponseObject, error) {
	if s.n == nil {
		return api.SetOrgNotificationSettings403JSONResponse(forbidden("Not permitted.")), nil
	}
	grant, err := authz.Require(ctx, s.n.Authz, req.OrgId.String(), authz.Settings)
	if err != nil || grant.Role != authz.Owner {
		return api.SetOrgNotificationSettings403JSONResponse(forbidden("Only an Owner sets the org's notification defaults.")), nil
	}
	raw, fields := channelsJSON(req.Body.Channels)
	if fields != nil {
		return api.SetOrgNotificationSettings400JSONResponse{ErrorJSONResponse: invalid("Some defaults are not valid.", fields)}, nil
	}
	var o store.OrgSetting
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		o, err = store.New(tx).UpsertOrgSettings(ctx, store.UpsertOrgSettingsParams{OrgID: req.OrgId, Channels: raw, PreviewsAllowed: req.Body.PreviewsAllowed})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.SetOrgNotificationSettings200JSONResponse(toOrgSettings(o)), nil
}

// RegisterDevice records this device's push token for the caller's session.
func (s *Server) RegisterDevice(ctx context.Context, req api.RegisterDeviceRequestObject) (api.RegisterDeviceResponseObject, error) {
	me, c, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.RegisterDevice403JSONResponse(forbidden("Not permitted for this organization.")), nil
	}
	b := req.Body
	platform := string(b.Platform)
	if platform != "web" && platform != "android" && platform != "ios" {
		return api.RegisterDevice400JSONResponse{ErrorJSONResponse: invalid("Not a platform.", map[string]string{"platform": "web, android or ios"})}, nil
	}
	if b.Token == "" || len(b.Token) > 4000 {
		return api.RegisterDevice400JSONResponse{ErrorJSONResponse: invalid("A token is needed.", map[string]string{"token": "1 to 4000 characters"})}, nil
	}
	if platform == "web" {
		var sub notify.Subscription
		if json.Unmarshal([]byte(b.Token), &sub) != nil || sub.Endpoint == "" || sub.Keys.P256dh == "" || sub.Keys.Auth == "" {
			return api.RegisterDevice400JSONResponse{ErrorJSONResponse: invalid("A web push subscription, as JSON.", map[string]string{"token": "a PushSubscription"})}, nil
		}
	}
	version := pgtype.Text{}
	if b.AppVersion != nil {
		version = pgtype.Text{String: *b.AppVersion, Valid: true}
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var d store.Device
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		d, err = store.New(tx).UpsertDevice(ctx, store.UpsertDeviceParams{
			OrgID: req.OrgId, ID: id, MembershipID: me, UserID: c.UserID, SessionID: c.SessionID,
			Platform: platform, Token: b.Token, TokenHash: notify.TokenHash(b.Token), AppVersion: version,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.RegisterDevice201JSONResponse{Id: d.ID, Platform: d.Platform}, nil
}

// UnregisterDevice stops a device's pushes: on sign-out, or when the person
// turns them off on it.
func (s *Server) UnregisterDevice(ctx context.Context, req api.UnregisterDeviceRequestObject) (api.UnregisterDeviceResponseObject, error) {
	me, _, err := s.member(ctx, req.OrgId)
	if err != nil {
		return api.UnregisterDevice403JSONResponse{ErrorJSONResponse: forbidden("Not permitted for this organization.")}, nil
	}
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).DeleteDeviceByToken(ctx, store.DeleteDeviceByTokenParams{OrgID: req.OrgId, MembershipID: me, TokenHash: notify.TokenHash(req.Body.Token)})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.UnregisterDevice204Response{}, nil
}

// GetPushConfig is the key a browser subscribes to web push with.
func (s *Server) GetPushConfig(ctx context.Context, _ api.GetPushConfigRequestObject) (api.GetPushConfigResponseObject, error) {
	if s.n == nil || s.n.VAPIDPublic == "" {
		return api.GetPushConfig200JSONResponse{Enabled: false}, nil
	}
	key := s.n.VAPIDPublic
	return api.GetPushConfig200JSONResponse{Enabled: true, VapidPublicKey: &key}, nil
}

// Unsubscribe turns off one category's email for the person a signed link
// names, with no sign-in: the one-click unsubscribe an email carries.
func (s *Server) Unsubscribe(ctx context.Context, req api.UnsubscribeRequestObject) (api.UnsubscribeResponseObject, error) {
	if s.n == nil {
		return api.Unsubscribe400JSONResponse{ErrorJSONResponse: invalid("This link does not work here.", nil)}, nil
	}
	org, me, category, err := notify.ParseUnsubscribe(s.n.LinkKey, req.Token)
	if err != nil {
		return api.Unsubscribe400JSONResponse{ErrorJSONResponse: invalid("This unsubscribe link is not valid.", map[string]string{"token": "not one of ours"})}, nil
	}
	ctx = auth.WithCaller(ctx, auth.Caller{OrgID: org.String(), MembershipID: me.String()})
	p, o, err := s.readPreferences(ctx, org, me)
	if err != nil {
		return nil, err
	}
	channels := notify.Resolve(p.Channels, o.Channels)
	ch := channels[category]
	ch.Email = false
	channels[category] = ch
	raw, _ := json.Marshal(channels)
	err = s.cluster.Tx(ctx, org.String(), func(tx pgx.Tx) error {
		_, err := store.New(tx).UpsertPreferences(ctx, store.UpsertPreferencesParams{
			OrgID: org, MembershipID: me, Channels: raw, PushPreviews: p.PushPreviews, DigestMinute: p.DigestMinute,
			QuietEnabled: p.QuietEnabled, QuietStartMinute: p.QuietStartMinute, QuietEndMinute: p.QuietEndMinute, QuietDays: p.QuietDays, Muted: p.Muted,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.Unsubscribe200JSONResponse{Category: api.Category(category)}, nil
}

// EmitEvent is the HTTP intake, for a service that would rather not publish.
func (s *Server) EmitEvent(ctx context.Context, req api.EmitEventRequestObject) (api.EmitEventResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil || s.n == nil {
		return api.EmitEvent403JSONResponse(forbidden("Services only.")), nil
	}
	b := req.Body
	ev := notify.Event{ID: b.Id, OrgID: b.OrgId, Kind: b.Kind, Category: notify.Category(b.Category), Recipients: b.Recipients, Actor: b.Actor, Link: b.Link, ExpiresAt: b.ExpiresAt}
	if b.Audience != nil {
		ev.Audience = string(*b.Audience)
	}
	if b.Group != nil {
		ev.Group = *b.Group
	}
	if b.Data != nil {
		ev.Data = *b.Data
	}
	if b.Preview != nil {
		ev.Preview = *b.Preview
	}
	if err := ev.Validate(); err != nil {
		return api.EmitEvent400JSONResponse{ErrorJSONResponse: invalid("The event is not valid: it needs "+err.Error()+".", nil)}, nil
	}
	if err := s.n.Router.Handle(ctx, ev); err != nil {
		return nil, err
	}
	return api.EmitEvent202Response{}, nil
}
