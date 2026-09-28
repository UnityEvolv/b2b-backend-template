package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage"
	"github.com/UnityEvolv/b2b-backend-template/pkg/storage/images"
	"github.com/UnityEvolv/b2b-backend-template/pkg/timezone"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Profile fields (UO-57): what a person controls themselves, the same in
// every org they belong to. Directory attributes from an identity provider
// are the membership's and not editable here.

const (
	// photoSize is the stored photo's side: square, enough for any avatar.
	photoSize = 512
	// photoReadTTL is how long a signed link to a photo is good for.
	photoReadTTL = time.Hour
)

// photoURL is a signed link to a photo, or nil when there is none or no
// bucket. A link that cannot be signed is logged, not fatal: the profile
// still loads without the picture.
func (s *Server) photoURL(ctx context.Context, key pgtype.Text) *string {
	if !key.Valid || s.uploads == nil {
		return nil
	}
	k, err := storage.ParseKey(key.String)
	if err != nil {
		s.logger.Warn("photo key unreadable", "error", err)
		return nil
	}
	u, err := s.uploads.ReadURL(ctx, auth.PlatformOrg, k, photoReadTTL)
	if err != nil {
		s.logger.Warn("could not sign a photo link", "error", err)
		return nil
	}
	out := u.String()
	return &out
}

// profile is a user with the profile fields filled in.
func (s *Server) profile(ctx context.Context, u store.User) api.User {
	out := toUser(u)
	if u.DisplayName.Valid {
		out.DisplayName = &u.DisplayName.String
	}
	if u.TimeZone.Valid {
		out.TimeZone = &u.TimeZone.String
	}
	if len(u.WorkingHours) > 0 {
		var wh api.WorkingHours
		if err := json.Unmarshal(u.WorkingHours, &wh); err == nil {
			out.WorkingHours = &wh
		}
	}
	out.PhotoUrl = s.photoURL(ctx, u.PhotoKey)
	prefs := api.Preferences{Theme: api.PreferencesTheme(u.Theme)}
	if u.Language.Valid {
		prefs.Language.Set(u.Language.String)
	}
	out.Preferences = &prefs
	return out
}

var weekdays = map[api.WorkingHoursDays]bool{api.Mon: true, api.Tue: true, api.Wed: true, api.Thu: true, api.Fri: true, api.Sat: true, api.Sun: true}

// checkWorkingHours is whether a working-hours value makes sense.
func checkWorkingHours(wh api.WorkingHours) string {
	if len(wh.Days) == 0 || len(wh.Days) > 7 {
		return "one to seven days"
	}
	seen := map[api.WorkingHoursDays]bool{}
	for _, d := range wh.Days {
		if !weekdays[d] || seen[d] {
			return "days mon to sun, each once"
		}
		seen[d] = true
	}
	start, err1 := time.Parse("15:04", wh.Start)
	end, err2 := time.Parse("15:04", wh.End)
	if err1 != nil || err2 != nil {
		return "start and end as HH:MM"
	}
	if !end.After(start) {
		return "end after start"
	}
	return ""
}

// UpdateProfile changes the fields sent; null clears one.
func (s *Server) UpdateProfile(ctx context.Context, req api.UpdateProfileRequestObject) (api.UpdateProfileResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.UpdateProfile403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	userID, err := uuid.Parse(c.UserID)
	if err != nil {
		return api.UpdateProfile403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	var current store.User
	err = s.cluster.Read(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		current, err = store.New(tx).GetUser(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	body := req.Body
	fields := map[string]string{}
	params := store.UpdateProfileParams{
		ID: userID, DisplayName: current.DisplayName, TimeZone: current.TimeZone, WorkingHours: current.WorkingHours,
		Theme: current.Theme, Language: current.Language,
	}
	if body.Theme != nil {
		switch *body.Theme {
		case api.ProfileUpdateThemeLight, api.ProfileUpdateThemeDark, api.ProfileUpdateThemeSystem:
			params.Theme = string(*body.Theme)
		default:
			fields["theme"] = "light, dark or system"
		}
	}
	if body.Language.IsSpecified() {
		params.Language = pgtype.Text{}
		if !body.Language.IsNull() {
			v := strings.TrimSpace(body.Language.MustGet())
			if len(v) < 2 || len(v) > 35 {
				fields["language"] = "a language tag such as en or pt-BR"
			}
			params.Language = pgtype.Text{String: v, Valid: true}
		}
	}
	if body.DisplayName.IsSpecified() {
		params.DisplayName = pgtype.Text{}
		if !body.DisplayName.IsNull() {
			v := strings.TrimSpace(body.DisplayName.MustGet())
			if v == "" || len(v) > 60 {
				fields["display_name"] = "one to sixty characters"
			}
			params.DisplayName = pgtype.Text{String: v, Valid: true}
		}
	}
	if body.TimeZone.IsSpecified() {
		params.TimeZone = pgtype.Text{}
		if !body.TimeZone.IsNull() {
			v := strings.TrimSpace(body.TimeZone.MustGet())
			if err := timezone.Validate(v); err != nil {
				fields["time_zone"] = "an IANA zone name, such as Europe/London"
			}
			params.TimeZone = pgtype.Text{String: v, Valid: true}
		}
	}
	if body.WorkingHours.IsSpecified() {
		params.WorkingHours = nil
		if !body.WorkingHours.IsNull() {
			wh := body.WorkingHours.MustGet()
			if reason := checkWorkingHours(wh); reason != "" {
				fields["working_hours"] = reason
			}
			params.WorkingHours, _ = json.Marshal(wh)
		}
	}
	if len(fields) > 0 {
		return api.UpdateProfile400JSONResponse{ErrorJSONResponse: invalid("The profile could not be saved.", fields)}, nil
	}
	var updated store.User
	err = s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		var err error
		updated, err = store.New(tx).UpdateProfile(ctx, params)
		return err
	})
	if err != nil {
		return nil, err
	}
	return api.UpdateProfile200JSONResponse(s.profile(ctx, updated)), nil
}

// readPhotoPart is the photo part of the upload, its declared type, and
// its bytes, read no further than the purpose allows.
func readPhotoPart(r *multipart.Reader) (contentType string, data []byte, err error) {
	for {
		part, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			return "", nil, errors.New("no photo part")
		}
		if err != nil {
			return "", nil, err
		}
		if part.FormName() != "photo" {
			continue
		}
		limit := storage.ProfilePhoto.MaxBytes
		data, err := io.ReadAll(io.LimitReader(part, limit+1))
		if err != nil {
			return "", nil, err
		}
		if int64(len(data)) > limit {
			return "", nil, errTooLarge
		}
		ct := part.Header.Get("Content-Type")
		if ct == "" {
			ct = http.DetectContentType(data)
		}
		return ct, data, nil
	}
}

var errTooLarge = errors.New("too large")

// SetPhoto stores a square, resized copy of the upload and drops the old.
func (s *Server) SetPhoto(ctx context.Context, req api.SetPhotoRequestObject) (api.SetPhotoResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.SetPhoto403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	if s.uploads == nil {
		return nil, errors.New("no upload bucket is configured")
	}
	userID, _ := uuid.Parse(c.UserID)
	contentType, data, err := readPhotoPart(req.Body)
	if errors.Is(err, errTooLarge) {
		return api.SetPhoto413JSONResponse{Code: "photo.too_large", Message: fmt.Sprintf("The photo must be at most %d MB.", storage.ProfilePhoto.MaxBytes>>20)}, nil
	}
	if err != nil {
		return api.SetPhoto400JSONResponse{ErrorJSONResponse: invalid("Send the photo as a part named photo.", map[string]string{"photo": "a JPEG, PNG or WebP file"})}, nil
	}
	if err := storage.ProfilePhoto.Validate(contentType, int64(len(data))); err != nil {
		return api.SetPhoto400JSONResponse{ErrorJSONResponse: invalid("That is not a photo this accepts.", map[string]string{"photo": "a JPEG, PNG or WebP file of at most 5 MB"})}, nil
	}
	img, _, err := images.Decode(bytes.NewReader(data))
	if err != nil {
		return api.SetPhoto400JSONResponse{ErrorJSONResponse: invalid("The photo could not be read.", map[string]string{"photo": "a JPEG, PNG or WebP image"})}, nil
	}
	encoded, storedType, err := images.Encode(images.Square(img, photoSize), false)
	if err != nil {
		return nil, err
	}
	key, err := storage.NewKey(auth.PlatformOrg, storage.ProfilePhoto)
	if err != nil {
		return nil, err
	}
	if err := s.uploads.Put(ctx, auth.PlatformOrg, key, storedType, int64(len(encoded)), bytes.NewReader(encoded)); err != nil {
		return nil, err
	}
	var previous, updated store.User
	err = s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if previous, err = q.GetUser(ctx, userID); err != nil {
			return err
		}
		updated, err = q.SetPhotoKey(ctx, store.SetPhotoKeyParams{ID: userID, PhotoKey: pgtype.Text{String: key.String(), Valid: true}})
		return err
	})
	if err != nil {
		_ = s.uploads.Delete(ctx, auth.PlatformOrg, key)
		return nil, err
	}
	s.dropPhoto(ctx, previous.PhotoKey)
	return api.SetPhoto200JSONResponse(s.profile(ctx, updated)), nil
}

// dropPhoto deletes an old photo's object. Best effort: a leftover object
// costs a little storage; a failed request would cost the person their
// new photo.
func (s *Server) dropPhoto(ctx context.Context, key pgtype.Text) {
	if !key.Valid || s.uploads == nil {
		return
	}
	k, err := storage.ParseKey(key.String)
	if err == nil {
		err = s.uploads.Delete(ctx, auth.PlatformOrg, k)
	}
	if err != nil {
		s.logger.Warn("could not delete an old photo", "error", err)
	}
}

// DeletePhoto removes the photo, if there is one.
func (s *Server) DeletePhoto(ctx context.Context, _ api.DeletePhotoRequestObject) (api.DeletePhotoResponseObject, error) {
	c, ok := requireCaller(ctx)
	if !ok {
		return api.DeletePhoto403JSONResponse{Code: httpx.CodeForbidden, Message: "A person's session only."}, nil
	}
	userID, _ := uuid.Parse(c.UserID)
	var previous store.User
	err := s.cluster.Tx(ctx, auth.PlatformOrg, func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if previous, err = q.GetUser(ctx, userID); err != nil {
			return err
		}
		_, err = q.SetPhotoKey(ctx, store.SetPhotoKeyParams{ID: userID})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.DeletePhoto204Response{}, nil
	}
	if err != nil {
		return nil, err
	}
	s.dropPhoto(ctx, previous.PhotoKey)
	return api.DeletePhoto204Response{}, nil
}
