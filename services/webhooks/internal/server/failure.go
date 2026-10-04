package server

import (
	"encoding/json"
	"net/http"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
	"github.com/UnityEvolv/b2b-backend-template/services/webhooks/internal/api"
)

// failure is any refusal, in the error envelope: a missing permission, a
// plan without webhooks, a bad field, something not found. It answers for
// every operation, so a handler returns the one value whatever its
// generated response types are.
type failure struct {
	status int
	body   api.Error
}

func fail(status int, code, message string, fields map[string]string) *failure {
	return &failure{status: status, body: errBody(code, message, fields)}
}

func notFound(what string) *failure {
	return fail(http.StatusNotFound, codeNotFound, "No such "+what+".", nil)
}

func invalid(message string, fields map[string]string) *failure {
	return fail(http.StatusBadRequest, httpx.CodeInvalidRequest, message, fields)
}

func (f *failure) write(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	return json.NewEncoder(w).Encode(f.body)
}

func (f *failure) VisitPurgeOrgDataResponse(w http.ResponseWriter) error          { return f.write(w) }
func (f *failure) VisitExportOrgDataResponse(w http.ResponseWriter) error         { return f.write(w) }
func (f *failure) VisitEmitWebhookEventResponse(w http.ResponseWriter) error      { return f.write(w) }
func (f *failure) VisitExportUserDataResponse(w http.ResponseWriter) error        { return f.write(w) }
func (f *failure) VisitListWebhookDeliveriesResponse(w http.ResponseWriter) error { return f.write(w) }
func (f *failure) VisitGetWebhookDeliveryResponse(w http.ResponseWriter) error    { return f.write(w) }
func (f *failure) VisitResendWebhookDeliveryResponse(w http.ResponseWriter) error { return f.write(w) }
func (f *failure) VisitListWebhookEndpointsResponse(w http.ResponseWriter) error  { return f.write(w) }
func (f *failure) VisitCreateWebhookEndpointResponse(w http.ResponseWriter) error { return f.write(w) }
func (f *failure) VisitDeleteWebhookEndpointResponse(w http.ResponseWriter) error { return f.write(w) }
func (f *failure) VisitGetWebhookEndpointResponse(w http.ResponseWriter) error    { return f.write(w) }
func (f *failure) VisitUpdateWebhookEndpointResponse(w http.ResponseWriter) error { return f.write(w) }
func (f *failure) VisitRotateWebhookSecretResponse(w http.ResponseWriter) error   { return f.write(w) }
func (f *failure) VisitSendWebhookTestResponse(w http.ResponseWriter) error       { return f.write(w) }
func (f *failure) VisitListWebhookEventTypesResponse(w http.ResponseWriter) error { return f.write(w) }
