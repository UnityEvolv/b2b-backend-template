package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/authz"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/pkg/plan"
	"github.com/UnityEvolv/b2b-backend-template/pkg/sheet"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/user/internal/store"
)

// Bulk user import: an admin seeds many people from a spreadsheet.
// Every row is checked and reported; valid rows are sent invites; nothing
// is dropped silently.

// importMaxBytes is the largest spreadsheet taken. The invites it sends open
// the main app.
const importMaxBytes = 5 << 20

// mapping names the spreadsheet column for each field.
type mapping struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// readImport is the file and the mapping out of the multipart body.
func readImport(r *multipart.Reader) (file []byte, m mapping, err error) {
	m = mapping{Email: "email", Name: "name", Role: "role"}
	for {
		part, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, m, err
		}
		switch part.FormName() {
		case "file":
			data, err := io.ReadAll(io.LimitReader(part, importMaxBytes+1))
			if err != nil {
				return nil, m, err
			}
			if len(data) > importMaxBytes {
				return nil, m, errTooLarge
			}
			file = data
		case "mapping":
			raw, err := io.ReadAll(io.LimitReader(part, 4096))
			if err != nil {
				return nil, m, err
			}
			var given mapping
			if err := json.Unmarshal(raw, &given); err != nil {
				return nil, m, fmt.Errorf("mapping: %w", err)
			}
			if given.Email != "" {
				m.Email = given.Email
			}
			if given.Name != "" {
				m.Name = given.Name
			}
			if given.Role != "" {
				m.Role = given.Role
			}
		}
	}
	if file == nil {
		return nil, m, errors.New("no file part")
	}
	return file, m, nil
}

func rowError(code, message string) struct {
	Code    string `json:"code"`
	Message string `json:"message"`
} {
	return struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}
}

// ImportUsers checks every row and, unless a dry run, invites the valid ones.
func (s *Server) ImportUsers(ctx context.Context, req api.ImportUsersRequestObject) (api.ImportUsersResponseObject, error) {
	grant, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users)
	if err != nil {
		return api.ImportUsers403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to import users."}, nil
	}
	dryRun := req.Params.DryRun != nil && *req.Params.DryRun
	file, m, err := readImport(req.Body)
	if errors.Is(err, errTooLarge) {
		return api.ImportUsers413JSONResponse{Code: "import.too_large", Message: fmt.Sprintf("The file must be at most %d MB.", importMaxBytes>>20)}, nil
	}
	if err != nil {
		return api.ImportUsers400JSONResponse{ErrorJSONResponse: invalid("Send the spreadsheet as a part named file, and the mapping as JSON.", map[string]string{"file": "a CSV or XLSX", "mapping": err.Error()})}, nil
	}
	table, err := sheet.Read(file)
	switch {
	case errors.Is(err, sheet.ErrEmpty):
		return api.ImportUsers400JSONResponse{ErrorJSONResponse: invalid("The sheet has no rows.", map[string]string{"file": "a header row and at least one person"})}, nil
	case errors.Is(err, sheet.ErrTooLarge):
		return api.ImportUsers413JSONResponse{Code: "import.too_large", Message: fmt.Sprintf("At most %d rows and %d columns.", sheet.MaxRows-1, sheet.MaxColumns)}, nil
	case err != nil:
		return api.ImportUsers400JSONResponse{ErrorJSONResponse: invalid("The file could not be read.", map[string]string{"file": "a CSV or XLSX file"})}, nil
	}
	cols := map[string]int{"email": table.Column(m.Email), "name": table.Column(m.Name), "role": table.Column(m.Role)}
	missing := map[string]string{}
	if cols["email"] < 0 {
		missing["mapping.email"] = "no column named " + m.Email
	}
	if cols["name"] < 0 {
		missing["mapping.name"] = "no column named " + m.Name
	}
	if len(missing) > 0 {
		return api.ImportUsers400JSONResponse{ErrorJSONResponse: invalid("The sheet does not have the columns the mapping names.", missing)}, nil
	}

	// The plan's cap, read now: rows past it are reported, not dropped.
	band, err := s.plans.Band(ctx, req.OrgId.String())
	if err != nil {
		return nil, err
	}
	var active int64
	err = s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		active, err = store.New(tx).CountActiveMemberships(ctx, req.OrgId)
		return err
	})
	if err != nil {
		return nil, err
	}
	// A real import past the cap asks billing for room once, for the whole
	// sheet, so an org upgrades once per crossing rather than band by band.
	if !dryRun && s.capacity != nil && plan.For(band).Cap(plan.Users) != plan.Unlimited && int(active)+len(table.Rows) > plan.For(band).Cap(plan.Users) {
		ok, err := s.capacity.MakeRoom(ctx, req.OrgId, int(active)+len(table.Rows))
		if err != nil {
			return nil, err
		}
		if ok {
			if band, err = s.plans.Band(ctx, req.OrgId.String()); err != nil {
				return nil, err
			}
		}
	}
	room := plan.For(band).Cap(plan.Users) - int(active)
	if plan.For(band).Cap(plan.Users) == plan.Unlimited {
		room = len(table.Rows) + 1
	}

	c, _ := auth.CallerFrom(ctx)
	var invitedBy *uuid.UUID
	if id, err := uuid.Parse(c.MembershipID); err == nil {
		invitedBy = &id
	}
	out := api.ImportResult{DryRun: dryRun, Rows: []api.ImportRow{}}
	out.Summary.Rows = len(table.Rows)
	seen := map[string]bool{}
	for i, row := range table.Rows {
		r := api.ImportRow{Row: i + 2, Errors: []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}{}}
		address := normalizeEmail(sheet.Cell(row, cols["email"]))
		name := strings.TrimSpace(sheet.Cell(row, cols["name"]))
		roleText := strings.ToLower(strings.TrimSpace(sheet.Cell(row, cols["role"])))
		if raw := sheet.Cell(row, cols["email"]); raw != "" {
			r.Email = &raw
		}
		if name != "" {
			r.Name = &name
		}
		switch {
		case sheet.Cell(row, cols["email"]) == "":
			r.Errors = append(r.Errors, rowError("missing_email", "No email address."))
		case address == "":
			r.Errors = append(r.Errors, rowError("email_invalid", "Not an email address."))
		}
		switch {
		case name == "":
			r.Errors = append(r.Errors, rowError("missing_name", "No name."))
		case len(name) > 200:
			r.Errors = append(r.Errors, rowError("name_too_long", "The name is longer than 200 characters."))
		}
		// A blank cell is a User. Whatever the role, the importer must be
		// one who may invite it, as the identity service's own invite
		// checks; the internal invite it sends checks nothing.
		role := authz.User
		parsed, perr := authz.ParseRole(roleText)
		switch {
		case roleText != "" && (perr != nil || parsed == authz.Guest || parsed == authz.Owner):
			r.Errors = append(r.Errors, rowError("role_invalid", "Not a role you can give: user, admin or billing_admin."))
		default:
			if roleText != "" {
				role = parsed
			}
			if !authz.MayManage(grant.Role, role) {
				r.Errors = append(r.Errors, rowError("role_invalid", "You may not invite a "+strings.ReplaceAll(string(role), "_", " ")+"."))
			}
		}
		roleName := string(role)
		r.Role = &roleName
		if address != "" {
			if seen[address] {
				r.Errors = append(r.Errors, rowError("duplicate", "This address appears earlier in the sheet."))
			}
			seen[address] = true
		}
		if address != "" && len(r.Errors) == 0 {
			var existing store.GetMembershipByEmailRow
			err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
				var err error
				existing, err = store.New(tx).GetMembershipByEmail(ctx, store.GetMembershipByEmailParams{OrgID: req.OrgId, Email: address})
				return err
			})
			if err == nil && existing.Membership.Status == "active" {
				r.Errors = append(r.Errors, rowError("already_member", "Already a member of this organization."))
			} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
		}
		if len(r.Errors) == 0 {
			if room <= 0 {
				r.Errors = append(r.Errors, rowError("plan_limit", fmt.Sprintf("The %s plan's user limit is reached; the next plan up is %s.", band, plan.Next(band))))
			} else {
				room--
			}
		}
		if len(r.Errors) > 0 {
			r.Status = api.ImportRowStatusFailed
			out.Summary.Invalid++
			out.Rows = append(out.Rows, r)
			continue
		}
		out.Summary.Valid++
		if dryRun {
			r.Status = api.ImportRowStatusWouldInvite
			out.Rows = append(out.Rows, r)
			continue
		}
		err := s.invites.CreateInvite(ctx, NewInvite{OrgID: req.OrgId, Email: address, Role: roleName, InvitedByMembershipID: invitedBy})
		var refusal *InviteRefusal
		switch {
		case errors.As(err, &refusal):
			code := "invite_failed"
			if refusal.Code == "invite.already_member" {
				code = "already_member"
			}
			r.Status = api.ImportRowStatusFailed
			r.Errors = append(r.Errors, rowError(code, "The invitation could not be sent: "+refusal.Code+"."))
			out.Summary.Valid--
			out.Summary.Invalid++
		case err != nil:
			return nil, err
		default:
			r.Status = api.ImportRowStatusInvited
			out.Summary.Invited++
		}
		out.Rows = append(out.Rows, r)
	}
	if !dryRun {
		err := s.recorder.Record(ctx, audit.Event{
			OrgID: req.OrgId.String(), Action: "users.imported", TargetType: "organization", TargetID: req.OrgId.String(),
			Details: map[string]any{"rows": out.Summary.Rows, "invited": out.Summary.Invited, "invalid": out.Summary.Invalid},
		})
		if err != nil {
			return nil, err
		}
	}
	return api.ImportUsers200JSONResponse(out), nil
}

// importSample is how many rows the column reader shows under the header.
const importSample = 5

// ReadImportColumns reads a sheet's header and first rows so the admin can
// map its columns before importing. Nothing is stored or sent.
func (s *Server) ReadImportColumns(ctx context.Context, req api.ReadImportColumnsRequestObject) (api.ReadImportColumnsResponseObject, error) {
	if _, err := authz.Require(ctx, s.authz, req.OrgId.String(), authz.Users); err != nil {
		return api.ReadImportColumns403JSONResponse{Code: httpx.CodeForbidden, Message: "You do not have permission to import users."}, nil
	}
	file, _, err := readImport(req.Body)
	if errors.Is(err, errTooLarge) {
		return api.ReadImportColumns413JSONResponse{Code: "import.too_large", Message: fmt.Sprintf("The file must be at most %d MB.", importMaxBytes>>20)}, nil
	}
	if err != nil {
		return api.ReadImportColumns400JSONResponse{ErrorJSONResponse: invalid("Send the spreadsheet as a part named file.", map[string]string{"file": "a CSV or XLSX"})}, nil
	}
	table, err := sheet.Read(file)
	switch {
	case errors.Is(err, sheet.ErrEmpty):
		return api.ReadImportColumns400JSONResponse{ErrorJSONResponse: invalid("The sheet has no rows.", map[string]string{"file": "a header row and at least one person"})}, nil
	case errors.Is(err, sheet.ErrTooLarge):
		return api.ReadImportColumns413JSONResponse{Code: "import.too_large", Message: fmt.Sprintf("At most %d rows and %d columns.", sheet.MaxRows-1, sheet.MaxColumns)}, nil
	case err != nil:
		return api.ReadImportColumns400JSONResponse{ErrorJSONResponse: invalid("The file could not be read.", map[string]string{"file": "a CSV or XLSX file"})}, nil
	}
	out := api.ImportColumns{Columns: table.Header, Rows: len(table.Rows), Sample: [][]string{}}
	for i, row := range table.Rows {
		if i == importSample {
			break
		}
		out.Sample = append(out.Sample, row)
	}
	return api.ReadImportColumns200JSONResponse(out), nil
}
