package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/oapi-codegen/nullable"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/db"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// The frames endpoints (UO-147). Changing anything is an org admin's (the
// settings permission) or a platform operator's; seeing the frame that is
// showing is any member's.

const (
	codeFrameNotFound   = "frame.not_found"
	codeFrameNeedsDates = "frame.needs_dates"
	codeFrameLimit      = "frame.limit"
	// maxOrgFrames is how many frames of its own an org may keep.
	maxOrgFrames = 50
	// defaultFrameIcon is an org frame's icon when none is given.
	defaultFrameIcon = "confetti"
)

var iconShape = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

var errOrgNotFound = errors.New("organization not found")

func frameForbidden(message string) api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: httpx.CodeForbidden, Message: message}
}

func orgNotFound() api.ErrorJSONResponse {
	return api.ErrorJSONResponse{Code: "organization.not_found", Message: "No such organization."}
}

func storageUnavailable() api.Error {
	return api.Error{Code: codeImageUnavailable, Message: "Frame uploads are not available here."}
}

// zoneOf is the org's time zone, UTC if the stored name cannot be loaded
// (it was validated when set, so this is a safety net only).
func zoneOf(o store.Organization) *time.Location {
	if loc, err := time.LoadLocation(o.TimeZone); err == nil {
		return loc
	}
	return time.UTC
}

func date(t time.Time) openapi_types.Date { return openapi_types.Date{Time: t} }

// frameData is everything about an org's frames, read in one transaction.
type frameData struct {
	org      store.Organization
	settings []store.OrgFrameSetting
	frames   []store.OrgFrame
}

func (s *Server) readFrames(ctx context.Context, org uuid.UUID) (frameData, error) {
	var d frameData
	err := s.cluster.Read(ctx, org.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if d.org, err = q.GetOrganization(ctx, org); err != nil {
			return err
		}
		if d.settings, err = q.ListFrameSettings(ctx, org); err != nil {
			return err
		}
		d.frames, err = q.ListOrgFrames(ctx, org)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return d, errOrgNotFound
	}
	return d, err
}

// signFrameImages is short-lived links to an org frame's images.
func (s *Server) signFrameImages(ctx context.Context, f store.OrgFrame) (api.FrameImages, error) {
	if s.frames == nil {
		return api.FrameImages{}, errors.New("frame storage is not configured")
	}
	stored, err := imagesOf(f)
	if err != nil {
		return api.FrameImages{}, err
	}
	sign := func(img storedImage) (string, error) {
		key, err := storage.ParseKey(img.Key)
		if err != nil {
			return "", fmt.Errorf("frame %s: %w", f.ID, err)
		}
		u, err := s.frames.ReadURL(ctx, f.OrgID.String(), key, frameReadTTL)
		if err != nil {
			return "", fmt.Errorf("sign frame %s: %w", f.ID, err)
		}
		return u.String(), nil
	}
	var out [3]api.FrameImage
	for i, shape := range frameShapes {
		v := stored[shape]
		light, err := sign(v.Light)
		if err != nil {
			return api.FrameImages{}, err
		}
		out[i].Light = light
		if v.Dark != nil {
			dark, err := sign(*v.Dark)
			if err != nil {
				return api.FrameImages{}, err
			}
			out[i].Dark = &dark
		}
	}
	return api.FrameImages{Landscape: out[0], Square: out[1], Portrait: out[2]}, nil
}

func (s *Server) toOrgFrame(ctx context.Context, f store.OrgFrame) (api.OrgFrame, error) {
	imgs, err := s.signFrameImages(ctx, f)
	if err != nil {
		return api.OrgFrame{}, err
	}
	return api.OrgFrame{
		Id: f.ID, Name: f.Name, Icon: f.Icon, StartDate: date(f.StartDate.Time), EndDate: date(f.EndDate.Time),
		Images: imgs, CreatedAt: f.CreatedAt,
	}, nil
}

// GetFrameSettings is the admin view: every platform frame as it applies to
// the org, the org's own frames, and the switch.
func (s *Server) GetFrameSettings(ctx context.Context, req api.GetFrameSettingsRequestObject) (api.GetFrameSettingsResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.GetFrameSettings403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	d, err := s.readFrames(ctx, req.OrgId)
	if errors.Is(err, errOrgNotFound) {
		return api.GetFrameSettings404JSONResponse(orgNotFound()), nil
	}
	if err != nil {
		return nil, err
	}
	out := api.FrameSettings{
		DecorationsEnabled: !d.org.DecorationsOff, TimeZone: d.org.TimeZone,
		PlatformFrames: []api.PlatformFrame{}, OrgFrames: []api.OrgFrame{},
	}
	for _, st := range statesOf(d.settings) {
		out.PlatformFrames = append(out.PlatformFrames, toPlatformFrame(st))
	}
	for _, f := range d.frames {
		of, err := s.toOrgFrame(ctx, f)
		if err != nil {
			return nil, err
		}
		out.OrgFrames = append(out.OrgFrames, of)
	}
	return api.GetFrameSettings200JSONResponse(out), nil
}

// SetPlatformFrame turns a platform frame on or off for the org, and sets or
// resets its yearly dates.
func (s *Server) SetPlatformFrame(ctx context.Context, req api.SetPlatformFrameRequestObject) (api.SetPlatformFrameResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.SetPlatformFrame403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	def, ok := platformFrameByKey(req.FrameKey)
	if !ok {
		return api.SetPlatformFrame404JSONResponse(api.ErrorJSONResponse{Code: codeFrameNotFound, Message: "No such frame."}), nil
	}
	if req.Body == nil {
		return api.SetPlatformFrame400JSONResponse{ErrorJSONResponse: invalid("Say whether the frame is on.", map[string]string{"enabled": "true or false"})}, nil
	}
	body := req.Body
	// The dates go together: both left out, both null, or both MM-DD.
	datesSent := body.StartMd.IsSpecified() || body.EndMd.IsSpecified()
	resetDates := false
	var start, end string
	if datesSent {
		fields := map[string]string{}
		switch {
		case body.StartMd.IsNull() && body.EndMd.IsNull():
			resetDates = true
		case !body.StartMd.IsSpecified() || !body.EndMd.IsSpecified() || body.StartMd.IsNull() || body.EndMd.IsNull():
			fields["start_md"] = "send start_md and end_md together, both MM-DD or both null"
			fields["end_md"] = fields["start_md"]
		default:
			start, _ = body.StartMd.Get()
			end, _ = body.EndMd.Get()
			if !validMonthDay(start) {
				fields["start_md"] = "a month and day, MM-DD, such as 10-20"
			}
			if !validMonthDay(end) {
				fields["end_md"] = "a month and day, MM-DD, such as 10-24"
			}
		}
		if len(fields) > 0 {
			return api.SetPlatformFrame400JSONResponse{ErrorJSONResponse: invalid("The dates are not valid.", fields)}, nil
		}
	}

	var (
		before, after frameState
		notFound      bool
		needsDates    bool
	)
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		if _, err := q.GetOrganization(ctx, req.OrgId); errors.Is(err, pgx.ErrNoRows) {
			notFound = true
			return nil
		} else if err != nil {
			return err
		}
		var prior *store.OrgFrameSetting
		row, err := q.GetFrameSetting(ctx, store.GetFrameSettingParams{OrgID: req.OrgId, FrameKey: def.Key})
		if err == nil {
			prior = &row
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		before = stateOf(def, prior)

		next := store.UpsertFrameSettingParams{OrgID: req.OrgId, FrameKey: def.Key, Enabled: body.Enabled}
		switch {
		case resetDates:
		case datesSent:
			next.StartMd, next.EndMd = text(start), text(end)
		case prior != nil:
			next.StartMd, next.EndMd = prior.StartMd, prior.EndMd
		}
		if prior != nil {
			next.EnabledAt = prior.EnabledAt
		}
		// Turned on now: it goes ahead of every frame turned on earlier.
		if body.Enabled && !before.enabled {
			next.EnabledAt = pgtype.Timestamptz{Time: s.now(), Valid: true}
		}
		probe := store.OrgFrameSetting{Enabled: next.Enabled, StartMd: next.StartMd, EndMd: next.EndMd, EnabledAt: next.EnabledAt}
		if body.Enabled && !stateOf(def, &probe).enabled {
			needsDates = true
			return nil
		}
		saved, err := q.UpsertFrameSetting(ctx, next)
		if err != nil {
			return err
		}
		after = stateOf(def, &saved)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if notFound {
		return api.SetPlatformFrame404JSONResponse(orgNotFound()), nil
	}
	if needsDates {
		return api.SetPlatformFrame400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{
			Code: codeFrameNeedsDates, Message: "This frame has no dates of its own. Give it dates to turn it on.",
			Fields: &map[string]string{"start_md": "required to turn this frame on", "end_md": "required to turn this frame on"},
		}}, nil
	}
	record := func(action string, details map[string]any) error {
		return s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: action, TargetType: "frame", TargetID: def.Key, Details: details})
	}
	if before.enabled != after.enabled {
		action := "organization.frame_disabled"
		if after.enabled {
			action = "organization.frame_enabled"
		}
		if err := record(action, map[string]any{"frame_key": def.Key}); err != nil {
			return nil, err
		}
	}
	if before.start != after.start || before.end != after.end {
		if err := record("organization.frame_dates_changed", map[string]any{
			"frame_key": def.Key, "from": before.start + ".." + before.end, "to": after.start + ".." + after.end,
		}); err != nil {
			return nil, err
		}
	}
	return api.SetPlatformFrame200JSONResponse(toPlatformFrame(after)), nil
}

// SetDecorations is the one switch: off, and no frame shows at all.
func (s *Server) SetDecorations(ctx context.Context, req api.SetDecorationsRequestObject) (api.SetDecorationsResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.SetDecorations403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	if req.Body == nil {
		return api.SetDecorations400JSONResponse{ErrorJSONResponse: invalid("Say whether decorations are on.", map[string]string{"enabled": "true or false"})}, nil
	}
	var (
		wasOff   bool
		notFound bool
	)
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		o, err := q.GetOrganization(ctx, req.OrgId)
		if errors.Is(err, pgx.ErrNoRows) {
			notFound = true
			return nil
		}
		if err != nil {
			return err
		}
		wasOff = o.DecorationsOff
		if wasOff == !req.Body.Enabled {
			return nil
		}
		_, err = q.SetDecorationsOff(ctx, store.SetDecorationsOffParams{OrgID: req.OrgId, DecorationsOff: !req.Body.Enabled})
		return err
	})
	if err != nil {
		return nil, err
	}
	if notFound {
		return api.SetDecorations404JSONResponse(orgNotFound()), nil
	}
	if wasOff != !req.Body.Enabled {
		if err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "organization.decorations_toggled", TargetType: "organization", TargetID: req.OrgId.String(),
			Details: map[string]any{"enabled": req.Body.Enabled},
		}); err != nil {
			return nil, err
		}
	}
	return api.SetDecorations200JSONResponse(api.Decorations{Enabled: req.Body.Enabled}), nil
}

// CreateFrameUploads is one pre-signed upload per image the client will
// send. Nothing is recorded: the images are checked when a frame names them.
func (s *Server) CreateFrameUploads(ctx context.Context, req api.CreateFrameUploadsRequestObject) (api.CreateFrameUploadsResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.CreateFrameUploads403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	if s.frames == nil {
		return api.CreateFrameUploadsdefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: storageUnavailable()}, nil
	}
	if req.Body == nil || len(req.Body.Files) == 0 || len(req.Body.Files) > 6 {
		return api.CreateFrameUploads400JSONResponse{ErrorJSONResponse: invalid("Ask for 1 to 6 files.", map[string]string{"files": "1 to 6 files, each shape and variant at most once"})}, nil
	}
	fields := map[string]string{}
	seen := map[string]bool{}
	for i, f := range req.Body.Files {
		at := fmt.Sprintf("files[%d]", i)
		if _, ok := frameBounds[string(f.Shape)]; !ok {
			fields[at+".shape"] = "landscape, square or portrait"
		}
		if f.Variant != api.Light && f.Variant != api.Dark {
			fields[at+".variant"] = "light or dark"
		}
		if seen[string(f.Shape)+"/"+string(f.Variant)] {
			fields[at] = "each shape and variant at most once"
		}
		seen[string(f.Shape)+"/"+string(f.Variant)] = true
		if err := framePurpose.Validate(f.ContentType, f.Size); err != nil {
			fields[at] = fmt.Sprintf("a PNG or WebP (image/png, image/webp) of 1 byte to %d MB", framePurpose.MaxBytes>>20)
		}
	}
	if len(fields) > 0 {
		return api.CreateFrameUploads400JSONResponse{ErrorJSONResponse: invalid("Some files cannot be frame images.", fields)}, nil
	}
	expires := s.now().Add(frameUploadTTL)
	out := api.FrameUploads{Uploads: make([]api.FrameUpload, 0, len(req.Body.Files))}
	for _, f := range req.Body.Files {
		key, err := storage.NewKey(req.OrgId.String(), framePurpose)
		if err != nil {
			return nil, err
		}
		contentType := strings.ToLower(strings.TrimSpace(strings.Split(f.ContentType, ";")[0]))
		u, err := s.frames.UploadURL(ctx, req.OrgId.String(), key, contentType, f.Size, frameUploadTTL)
		if err != nil {
			return nil, err
		}
		out.Uploads = append(out.Uploads, api.FrameUpload{
			Shape: f.Shape, Variant: f.Variant, Key: key.String(), UploadUrl: u.String(), ContentType: contentType, ExpiresAt: expires,
		})
	}
	return api.CreateFrameUploads200JSONResponse(out), nil
}

// CreateOrgFrame adds a frame of the org's own, once every image it names
// has been fetched and checked.
func (s *Server) CreateOrgFrame(ctx context.Context, req api.CreateOrgFrameRequestObject) (api.CreateOrgFrameResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.CreateOrgFrame403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	if req.Body == nil {
		return api.CreateOrgFrame400JSONResponse{ErrorJSONResponse: invalid("Send the frame.", nil)}, nil
	}
	body := req.Body
	fields := map[string]string{}
	name := strings.TrimSpace(body.Name)
	if name == "" || len([]rune(name)) > 100 {
		fields["name"] = "1 to 100 characters"
	}
	icon := defaultFrameIcon
	if body.Icon != nil {
		icon = strings.TrimSpace(*body.Icon)
		if !iconShape.MatchString(icon) {
			fields["icon"] = "an icon name: lower-case letters, digits and dashes"
		}
	}
	start, okStart := parseDay(body.StartDate)
	end, okEnd := parseDay(body.EndDate)
	if !okStart {
		fields["start_date"] = "a date, YYYY-MM-DD"
	}
	if !okEnd {
		fields["end_date"] = "a date, YYYY-MM-DD"
	}
	if okStart && okEnd && end.Before(start) {
		fields["end_date"] = "on or after the start date"
	}
	named := map[string]api.NewOrgFrameImage{"landscape": body.Images.Landscape, "square": body.Images.Square, "portrait": body.Images.Portrait}
	for _, shape := range frameShapes {
		if strings.TrimSpace(named[shape].Light) == "" {
			fields["images."+shape+".light"] = "required: every shape needs a light image"
		}
	}
	key := strings.TrimSpace(req.Params.IdempotencyKey)
	if key == "" || len(key) > 200 {
		fields["Idempotency-Key"] = "1 to 200 characters"
	}
	if len(fields) > 0 {
		return api.CreateOrgFrame400JSONResponse{ErrorJSONResponse: invalid("Some fields are not valid.", fields)}, nil
	}
	actor, _ := db.ActorFrom(ctx)
	byKey := store.OrgFrameByIdempotencyKeyParams{OrgID: req.OrgId, CreatedBy: string(actor), IdempotencyKey: text(key)}

	// A replay answers with what the first request made, before anything
	// the first request has since made true (the limit) is checked again.
	var (
		prior    store.OrgFrame
		replayed bool
		count    int64
	)
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		prior, err = q.OrgFrameByIdempotencyKey(ctx, byKey)
		if err == nil {
			replayed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		count, err = q.CountOrgFrames(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return s.replayOrgFrame(ctx, prior, name, start, end)
	}
	if count >= maxOrgFrames {
		return api.CreateOrgFrame409JSONResponse(api.ErrorJSONResponse{Code: codeFrameLimit, Message: fmt.Sprintf("An organization keeps at most %d frames of its own. Remove one first.", maxOrgFrames)}), nil
	}
	if s.frames == nil {
		return api.CreateOrgFramedefaultJSONResponse{StatusCode: http.StatusServiceUnavailable, Body: storageUnavailable()}, nil
	}

	// Every image fetched and checked, reporting every refusal at once.
	stored := storedImages{}
	var firstCode string
	for _, shape := range frameShapes {
		v := named[shape]
		check := func(variant, raw string) *storedImage {
			img, refused, err2 := s.checkFrameImage(ctx, req.OrgId.String(), shape, raw)
			if err2 != nil {
				err = err2
				return nil
			}
			if refused != nil {
				fields["images."+shape+"."+variant] = refused.message
				if firstCode == "" {
					firstCode = refused.code
				}
				return nil
			}
			return &img
		}
		var sv storedVariants
		if light := check("light", v.Light); light != nil {
			sv.Light = *light
		}
		if v.Dark != nil && strings.TrimSpace(*v.Dark) != "" {
			sv.Dark = check("dark", *v.Dark)
		}
		if err != nil {
			return nil, err
		}
		stored[shape] = sv
	}
	if len(fields) > 0 {
		return api.CreateOrgFrame400JSONResponse{ErrorJSONResponse: api.ErrorJSONResponse{Code: firstCode, Message: "Some images cannot be frame images.", Fields: &fields}}, nil
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	var row store.OrgFrame
	err = s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		row, err = q.InsertOrgFrame(ctx, store.InsertOrgFrameParams{
			OrgID: req.OrgId, ID: id, Name: name, Icon: icon,
			StartDate: pgtype.Date{Time: start, Valid: true}, EndDate: pgtype.Date{Time: end, Valid: true},
			Images: raw, IdempotencyKey: text(key),
		})
		if errors.Is(err, pgx.ErrNoRows) {
			// Two retries raced; the other one won.
			replayed = true
			row, err = q.OrgFrameByIdempotencyKey(ctx, byKey)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if replayed {
		return s.replayOrgFrame(ctx, row, name, start, end)
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "organization.frame_created", TargetType: "frame", TargetID: row.ID.String(),
		Details: map[string]any{"start_date": body.StartDate, "end_date": body.EndDate},
	}); err != nil {
		return nil, err
	}
	out, err := s.toOrgFrame(ctx, row)
	if err != nil {
		return nil, err
	}
	return api.CreateOrgFrame201JSONResponse(out), nil
}

// replayOrgFrame answers a retried create with the frame the first request
// made, or refuses a key reused for a different frame.
func (s *Server) replayOrgFrame(ctx context.Context, prior store.OrgFrame, name string, start, end time.Time) (api.CreateOrgFrameResponseObject, error) {
	if prior.Name != name || !prior.StartDate.Time.Equal(start) || !prior.EndDate.Time.Equal(end) {
		return api.CreateOrgFrame409JSONResponse(api.ErrorJSONResponse{Code: codeKeyReused, Message: "This idempotency key was already used for a different request."}), nil
	}
	out, err := s.toOrgFrame(ctx, prior)
	if err != nil {
		return nil, err
	}
	return api.CreateOrgFrame201JSONResponse(out), nil
}

// DeleteOrgFrame removes one of the org's own frames, and then its images.
func (s *Server) DeleteOrgFrame(ctx context.Context, req api.DeleteOrgFrameRequestObject) (api.DeleteOrgFrameResponseObject, error) {
	if err := s.readsSettings(ctx, req.OrgId); err != nil {
		return api.DeleteOrgFrame403JSONResponse(frameForbidden("You do not have permission to manage the organization's frames.")), nil
	}
	var row store.OrgFrame
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).DeleteOrgFrame(ctx, store.DeleteOrgFrameParams{OrgID: req.OrgId, ID: req.FrameId})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.DeleteOrgFrame404JSONResponse(api.ErrorJSONResponse{Code: codeFrameNotFound, Message: "No such frame."}), nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{OrgID: req.OrgId.String(), Action: "organization.frame_deleted", TargetType: "frame", TargetID: row.ID.String()}); err != nil {
		return nil, err
	}
	// The row is gone, so nothing shows the images; a file left behind by a
	// failure here is removed with the org's files when the org is purged.
	if s.frames != nil {
		if stored, err := imagesOf(row); err == nil {
			for _, v := range stored {
				for _, img := range []*storedImage{&v.Light, v.Dark} {
					if img == nil {
						continue
					}
					if key, err := storage.ParseKey(img.Key); err == nil {
						if err := s.frames.Delete(ctx, req.OrgId.String(), key); err != nil {
							s.logger.Error("frame image not deleted", "org_id", req.OrgId, "frame_id", row.ID, "error", err)
						}
					}
				}
			}
		}
	}
	return api.DeleteOrgFrame204Response{}, nil
}

// GetActiveFrame is the one frame showing over the office on a date: the
// org's own frame first, then the platform frame most recently turned on.
func (s *Server) GetActiveFrame(ctx context.Context, req api.GetActiveFrameRequestObject) (api.GetActiveFrameResponseObject, error) {
	if err := auth.RequireOrgOrPlatform(ctx, req.OrgId.String()); err != nil {
		return api.GetActiveFrame403JSONResponse(frameForbidden("Not permitted for this organization.")), nil
	}
	var asked *time.Time
	if req.Params.Date != nil {
		d, ok := parseDay(*req.Params.Date)
		if !ok {
			return api.GetActiveFrame400JSONResponse{ErrorJSONResponse: invalid("The date is not valid.", map[string]string{"date": "a date, YYYY-MM-DD"})}, nil
		}
		asked = &d
	}
	var (
		org      store.Organization
		settings []store.OrgFrameSetting
		own      *store.OrgFrame
		day      time.Time
	)
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if org, err = q.GetOrganization(ctx, req.OrgId); err != nil {
			return err
		}
		day = dayIn(s.now(), zoneOf(org))
		if asked != nil {
			day = *asked
		}
		if org.DecorationsOff {
			return nil
		}
		f, err := q.ActiveOrgFrame(ctx, store.ActiveOrgFrameParams{OrgID: req.OrgId, Day: pgtype.Date{Time: day, Valid: true}})
		if err == nil {
			own = &f
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		settings, err = q.ListFrameSettings(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetActiveFrame404JSONResponse(orgNotFound()), nil
	}
	if err != nil {
		return nil, err
	}
	out := api.ActiveFrameResponse{Date: date(day), Frame: nullable.NewNullNullable[api.ActiveFrame]()}
	switch {
	case org.DecorationsOff:
	case own != nil:
		imgs, err := s.signFrameImages(ctx, *own)
		if err != nil {
			return nil, err
		}
		id := own.ID
		out.Frame = nullable.NewNullableWithValue(api.ActiveFrame{
			Kind: api.ActiveFrameKindOrganization, Id: &id, Name: own.Name, Icon: own.Icon,
			StartDate: date(own.StartDate.Time), EndDate: date(own.EndDate.Time), Images: imgs,
		})
	default:
		if st, ok := showingPlatform(day, statesOf(settings)); ok {
			from, to := occurrence(day, st.start, st.end)
			k := api.PlatformFrameKey(st.frame.Key)
			out.Frame = nullable.NewNullableWithValue(api.ActiveFrame{
				Kind: api.ActiveFrameKindPlatform, Key: &k, Name: st.frame.Name, Icon: st.frame.Icon,
				StartDate: date(from), EndDate: date(to), Images: platformImages(st.frame.Key),
			})
		}
	}
	return api.GetActiveFrame200JSONResponse(out), nil
}
