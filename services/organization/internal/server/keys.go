package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/UnityEvolv/b2b-backend-template/pkg/audit"
	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/envelope"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/api"
	"github.com/UnityEvolv/b2b-backend-template/services/organization/internal/store"
)

// decryptingServices are the only services that may fetch a wrapped key.
// KMS IAM on each service's identity is the second, independent gate: a
// service that fetched a wrapped key it may not unwrap has nothing.
var decryptingServices = []string{"identity"}

func (s *Server) requireDecryptingService(ctx context.Context) error {
	return auth.RequireService(ctx, decryptingServices...)
}

// EnsureDataKey gives an org its first data key, if it has none. Called when
// an org is created, inside that transaction.
func (s *Server) EnsureDataKey(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	q := store.New(tx)
	if _, err := q.CurrentOrgDataKey(ctx, orgID); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	_, err := s.addKeyVersion(ctx, q, orgID, 1)
	return err
}

func (s *Server) addKeyVersion(ctx context.Context, q *store.Queries, orgID uuid.UUID, version int32) (store.InsertOrgDataKeyRow, error) {
	dataKey, err := envelope.NewDataKey()
	if err != nil {
		return store.InsertOrgDataKeyRow{}, err
	}
	wrapped, kmsVersion, err := s.wrapper.Wrap(ctx, dataKey)
	if err != nil {
		return store.InsertOrgDataKeyRow{}, fmt.Errorf("wrap data key: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return store.InsertOrgDataKeyRow{}, err
	}
	return q.InsertOrgDataKey(ctx, store.InsertOrgDataKeyParams{
		OrgID: orgID, ID: id, Version: version, WrappedKey: wrapped, KmsKeyVersion: kmsVersion,
	})
}

func toWrapped(orgID uuid.UUID, version int32, wrapped []byte, kmsVersion string) api.WrappedDataKey {
	return api.WrappedDataKey{OrgId: orgID, Version: int(version), WrappedKey: wrapped, KmsKeyVersion: kmsVersion}
}

// GetCurrentDataKey is the org's current wrapped key, for a decrypting service.
func (s *Server) GetCurrentDataKey(ctx context.Context, req api.GetCurrentDataKeyRequestObject) (api.GetCurrentDataKeyResponseObject, error) {
	if err := s.requireDecryptingService(ctx); err != nil {
		return api.GetCurrentDataKey403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a service that decrypts may fetch a key."}, nil
	}
	var row store.CurrentOrgDataKeyRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).CurrentOrgDataKey(ctx, req.OrgId)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetCurrentDataKey404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetCurrentDataKey200JSONResponse(toWrapped(row.OrgID, row.Version, row.WrappedKey, row.KmsKeyVersion)), nil
}

// GetDataKeyVersion is one version of the org's wrapped key.
func (s *Server) GetDataKeyVersion(ctx context.Context, req api.GetDataKeyVersionRequestObject) (api.GetDataKeyVersionResponseObject, error) {
	if err := s.requireDecryptingService(ctx); err != nil {
		return api.GetDataKeyVersion403JSONResponse{Code: httpx.CodeForbidden, Message: "Only a service that decrypts may fetch a key."}, nil
	}
	var row store.OrgDataKeyVersionRow
	err := s.cluster.Read(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		var err error
		row, err = store.New(tx).OrgDataKeyVersion(ctx, store.OrgDataKeyVersionParams{OrgID: req.OrgId, Version: int32(req.Version)})
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.GetDataKeyVersion404JSONResponse{Code: "organization.key_not_found", Message: "No such key version."}, nil
	}
	if err != nil {
		return nil, err
	}
	return api.GetDataKeyVersion200JSONResponse(toWrapped(row.OrgID, row.Version, row.WrappedKey, row.KmsKeyVersion)), nil
}

// RotateDataKey adds a new current version. Earlier versions stay readable
// until every secret under them is re-encrypted; retiring them is a later
// pass. Audited, since it is a security action.
func (s *Server) RotateDataKey(ctx context.Context, req api.RotateDataKeyRequestObject) (api.RotateDataKeyResponseObject, error) {
	if err := auth.RequireService(ctx); err != nil {
		return api.RotateDataKey403JSONResponse{Code: httpx.CodeForbidden, Message: "Not permitted."}, nil
	}
	var row store.InsertOrgDataKeyRow
	err := s.cluster.Tx(ctx, req.OrgId.String(), func(tx pgx.Tx) error {
		q := store.New(tx)
		current, err := q.CurrentOrgDataKey(ctx, req.OrgId)
		if err != nil {
			return err
		}
		row, err = s.addKeyVersion(ctx, q, req.OrgId, current.Version+1)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return api.RotateDataKey404JSONResponse{Code: "organization.not_found", Message: "No such organization."}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.recorder.Record(ctx, audit.Event{
		OrgID: req.OrgId.String(), Action: "organization.data_key.rotated",
		TargetType: "organization", TargetID: req.OrgId.String(),
		Details: map[string]any{"version": row.Version},
	}); err != nil {
		return nil, err
	}
	return api.RotateDataKey201JSONResponse(toWrapped(row.OrgID, row.Version, row.WrappedKey, row.KmsKeyVersion)), nil
}
