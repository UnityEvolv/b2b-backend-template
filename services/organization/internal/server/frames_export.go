package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/orgdata"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// The org's frames in its export (UO-184, UO-147): its choices about the
// platform's frames, its own frames, and their images as files.

type exportedFrameSetting struct {
	FrameKey  string     `json:"frame_key"`
	Enabled   bool       `json:"enabled"`
	StartMD   *string    `json:"start_md,omitempty"`
	EndMD     *string    `json:"end_md,omitempty"`
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
}

type exportedOrgFrame struct {
	ID        uuid.UUID    `json:"id"`
	Name      string       `json:"name"`
	Icon      string       `json:"icon"`
	StartDate string       `json:"start_date"`
	EndDate   string       `json:"end_date"`
	Images    storedImages `json:"images"`
	CreatedAt time.Time    `json:"created_at"`
}

type exportedFrames struct {
	DecorationsEnabled bool                   `json:"decorations_enabled"`
	Settings           []exportedFrameSetting `json:"platform_frame_settings"`
	Frames             []exportedOrgFrame     `json:"org_frames"`
}

func (s *Server) exportFrames(ctx context.Context, o store.Organization) (exportedFrames, []orgdata.File, error) {
	out := exportedFrames{DecorationsEnabled: !o.DecorationsOff, Settings: []exportedFrameSetting{}, Frames: []exportedOrgFrame{}}
	var (
		settings []store.OrgFrameSetting
		frames   []store.OrgFrame
	)
	err := s.cluster.Read(ctx, o.OrgID.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		var err error
		if settings, err = q.ListFrameSettings(ctx, o.OrgID); err != nil {
			return err
		}
		frames, err = q.ListOrgFrames(ctx, o.OrgID)
		return err
	})
	if err != nil {
		return out, nil, err
	}
	for _, r := range settings {
		e := exportedFrameSetting{FrameKey: r.FrameKey, Enabled: r.Enabled}
		if r.StartMd.Valid {
			e.StartMD, e.EndMD = &r.StartMd.String, &r.EndMd.String
		}
		if r.EnabledAt.Valid {
			e.EnabledAt = &r.EnabledAt.Time
		}
		out.Settings = append(out.Settings, e)
	}
	files := []orgdata.File{}
	for _, f := range frames {
		imgs, err := imagesOf(f)
		if err != nil {
			return out, nil, err
		}
		out.Frames = append(out.Frames, exportedOrgFrame{
			ID: f.ID, Name: f.Name, Icon: f.Icon, StartDate: f.StartDate.Time.Format("2006-01-02"), EndDate: f.EndDate.Time.Format("2006-01-02"),
			Images: imgs, CreatedAt: f.CreatedAt,
		})
		for shape, v := range imgs {
			files = append(files, orgdata.File{Key: v.Light.Key, Name: frameFileName(f.ID, shape, "light", v.Light.ContentType)})
			if v.Dark != nil {
				files = append(files, orgdata.File{Key: v.Dark.Key, Name: frameFileName(f.ID, shape, "dark", v.Dark.ContentType)})
			}
		}
	}
	return out, files, nil
}

// frameFileName is where a frame image goes in the archive.
func frameFileName(id uuid.UUID, shape, variant, contentType string) string {
	return fmt.Sprintf("frames/%s/%s-%s.%s", id, shape, variant, strings.TrimPrefix(contentType, "image/"))
}
