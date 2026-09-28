package plan

import (
	"net/http"

	"github.com/UnityEvolv/b2b-backend-template/pkg/httpx"
)

// WriteRefusal answers a request the plan refused: 403 in the error
// envelope, with the plan, what was hit and the band that would allow it in
// fields, so the client can show the message and offer the upgrade.
func WriteRefusal(w http.ResponseWriter, r *Refusal) {
	httpx.WriteJSON(w, http.StatusForbidden, httpx.Error{Code: Code, Message: r.Message, Fields: r.Fields()})
}
