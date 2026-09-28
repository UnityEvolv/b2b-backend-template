package envelope

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/UnityEvolv/b2b-backend-template/pkg/auth"
	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// PlatformOrg is auth.PlatformOrg: the id a platform-wide pass that is not
// about one org, such as re-wrapping every key after a master rotation, runs
// under. It routes to shard 0 and is never a tenant.
const PlatformOrg = auth.PlatformOrg

// orgKeys fetches wrapped keys from the organization service's internal API,
// as this service. Whether the key then unwraps is KMS's decision.
type orgKeys struct {
	baseURL string
	tokens  auth.TokenSource
	http    *http.Client
}

// OrgKeys is a KeySource over the organization service at baseURL.
func OrgKeys(baseURL string, tokens auth.TokenSource, client *http.Client) KeySource {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &orgKeys{baseURL: baseURL, tokens: tokens, http: client}
}

func (o *orgKeys) Current(ctx context.Context, orgID string) (WrappedKey, error) {
	return o.fetch(ctx, o.baseURL+"/v1/internal/organizations/"+orgID+"/data-keys/current")
}

func (o *orgKeys) Version(ctx context.Context, orgID string, version uint32) (WrappedKey, error) {
	return o.fetch(ctx, o.baseURL+"/v1/internal/organizations/"+orgID+"/data-keys/"+strconv.FormatUint(uint64(version), 10))
}

func (o *orgKeys) fetch(ctx context.Context, url string) (WrappedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return WrappedKey{}, err
	}
	if err := auth.Authorize(ctx, o.tokens, req); err != nil {
		return WrappedKey{}, err
	}
	if info := httpx.RequestInfoFrom(ctx); info.ID != "" {
		req.Header.Set("X-Request-Id", info.ID)
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("envelope: fetch key: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var envelope httpx.Error
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&envelope)
		return WrappedKey{}, fmt.Errorf("envelope: fetch key: organization service answered %d %s", resp.StatusCode, envelope.Code)
	}
	var body struct {
		OrgID      string `json:"org_id"`
		Version    uint32 `json:"version"`
		WrappedKey []byte `json:"wrapped_key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		return WrappedKey{}, fmt.Errorf("envelope: fetch key: unreadable answer")
	}
	return WrappedKey{OrgID: body.OrgID, Version: body.Version, Wrapped: body.WrappedKey}, nil
}
