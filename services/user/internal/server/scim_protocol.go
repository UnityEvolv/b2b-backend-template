package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// SCIM 2.0 as RFC 7643 and 7644 define it: resources as plain JSON
// objects, attribute names matched without regard to case, filters and
// PATCH paths parsed here. Standards-shaped, so Entra, Okta and Google
// Workspace all work; where a provider bends the standard, the bend is
// accepted in one place and named (see "compat" below).

const (
	schemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	schemaList       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaPatch      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	schemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimContentType  = "application/scim+json"
	scimMaxPage      = 200
	scimMaxBody      = 1 << 20
)

// scimProblem is an error the provider is shown.
type scimProblem struct {
	status   int
	scimType string
	detail   string
}

func (p *scimProblem) Error() string { return p.detail }

func badRequest(scimType, detail string) *scimProblem {
	return &scimProblem{status: http.StatusBadRequest, scimType: scimType, detail: detail}
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeProblem(w http.ResponseWriter, p *scimProblem) {
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(p.status), "detail": p.detail}
	if p.scimType != "" {
		body["scimType"] = p.scimType
	}
	writeSCIM(w, p.status, body)
}

// readResource is a request body as a JSON object.
func readResource(r *http.Request) (map[string]any, *scimProblem) {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, scimMaxBody))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil || out == nil {
		return nil, badRequest("invalidSyntax", "The body is not a JSON object.")
	}
	return out, nil
}

// key is the key in m that names attribute name, ignoring case.
func key(m map[string]any, name string) (string, bool) {
	if _, ok := m[name]; ok {
		return name, true
	}
	for k := range m {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}
	return "", false
}

func get(m map[string]any, name string) any {
	if k, ok := key(m, name); ok {
		return m[k]
	}
	return nil
}

func set(m map[string]any, name string, v any) {
	if k, ok := key(m, name); ok {
		m[k] = v
		return
	}
	m[name] = v
}

func del(m map[string]any, name string) {
	if k, ok := key(m, name); ok {
		delete(m, k)
	}
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// boolean is v as a boolean. compat: Entra sends "True" and "False" as
// strings for active.
func boolean(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(t)))
		return b, err == nil
	}
	return false, false
}

// ---- Filters --------------------------------------------------------------

// condition is one "attribute eq value" of a filter.
type condition struct {
	path  string // lower-cased, with any [filter] on a multi-valued attribute kept
	value any
}

// parseFilter is the filters providers send: eq comparisons joined by and.
// Anything else is refused with invalidFilter, which the spec allows.
func parseFilter(s string) ([]condition, error) {
	var out []condition
	rest := strings.TrimSpace(s)
	for rest != "" {
		path, after, err := scanPath(rest)
		if err != nil {
			return nil, err
		}
		op, after := scanWord(after)
		if !strings.EqualFold(op, "eq") {
			return nil, fmt.Errorf("only eq is supported, not %q", op)
		}
		value, after, err := scanValue(after)
		if err != nil {
			return nil, err
		}
		out = append(out, condition{path: strings.ToLower(path), value: value})
		rest = strings.TrimSpace(after)
		if rest == "" {
			break
		}
		word, after := scanWord(rest)
		if !strings.EqualFold(word, "and") {
			return nil, fmt.Errorf("only and joins comparisons, not %q", word)
		}
		rest = strings.TrimSpace(after)
	}
	if len(out) == 0 {
		return nil, errors.New("an empty filter")
	}
	return out, nil
}

// scanPath reads an attribute path, which may carry a [filter] of its own.
func scanPath(s string) (string, string, error) {
	s = strings.TrimLeft(s, " ")
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote && c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == ' ' && depth == 0:
			if i == 0 {
				return "", "", errors.New("a filter needs an attribute")
			}
			return s[:i], s[i:], nil
		}
	}
	return "", "", errors.New("a filter needs an operator and a value")
}

func scanWord(s string) (string, string) {
	s = strings.TrimLeft(s, " ")
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func scanValue(s string) (any, string, error) {
	s = strings.TrimLeft(s, " ")
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if i+1 < len(s) {
					i++
					b.WriteByte(s[i])
				}
			case '"':
				return b.String(), s[i+1:], nil
			default:
				b.WriteByte(s[i])
			}
		}
		return nil, "", errors.New("an unterminated string")
	}
	word, rest := scanWord(s)
	switch strings.ToLower(word) {
	case "true":
		return true, rest, nil
	case "false":
		return false, rest, nil
	case "null":
		return nil, rest, nil
	}
	if _, err := strconv.ParseFloat(word, 64); err == nil {
		return json.Number(word), rest, nil
	}
	return nil, "", fmt.Errorf("%q is not a value", word)
}

// matches is whether one element of a multi-valued attribute meets conds.
func matches(el any, conds []condition) bool {
	m, ok := el.(map[string]any)
	if !ok {
		return false
	}
	for _, c := range conds {
		got := get(m, c.path)
		if want, ok := c.value.(string); ok {
			if !strings.EqualFold(str(got), want) {
				return false
			}
			continue
		}
		if b, ok := c.value.(bool); ok {
			if gb, ok := boolean(got); !ok || gb != b {
				return false
			}
			continue
		}
		if str(got) != str(c.value) {
			return false
		}
	}
	return true
}

// ---- PATCH ----------------------------------------------------------------

// patchOp is one operation of a PATCH request.
type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// readPatch is a PATCH body's operations.
func readPatch(r *http.Request) ([]patchOp, *scimProblem) {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, scimMaxBody))
	dec.UseNumber()
	var body struct {
		Operations []patchOp `json:"Operations"`
	}
	if err := dec.Decode(&body); err != nil {
		return nil, badRequest("invalidSyntax", "The body is not a PatchOp message.")
	}
	if len(body.Operations) == 0 {
		return nil, badRequest("invalidValue", "A PATCH needs at least one operation.")
	}
	for i := range body.Operations {
		body.Operations[i].Op = strings.ToLower(strings.TrimSpace(body.Operations[i].Op))
		switch body.Operations[i].Op {
		case "add", "replace", "remove":
		default:
			return nil, badRequest("invalidSyntax", fmt.Sprintf("%q is not a PATCH operation.", body.Operations[i].Op))
		}
	}
	return body.Operations, nil
}

// scimPath is a parsed PATCH path: urn:...:attr[filter].sub, every part optional
// except attr.
type scimPath struct {
	urn    string
	attr   string
	filter []condition
	sub    string
}

func parsePath(p string) (scimPath, error) {
	var out scimPath
	p = strings.TrimSpace(p)
	if strings.HasPrefix(strings.ToLower(p), "urn:") {
		// The extension's URN is everything up to the last colon outside a
		// filter; a path that is the URN alone names the whole extension.
		cut := strings.LastIndex(beforeBracket(p), ":")
		out.urn, p = p[:cut], p[cut+1:]
		if isSchema(out.urn + ":" + p) {
			return scimPath{attr: out.urn + ":" + p}, nil
		}
	}
	if i := strings.IndexByte(p, '['); i >= 0 {
		j := strings.LastIndexByte(p, ']')
		if j < i {
			return out, errors.New("an unclosed filter")
		}
		conds, err := parseFilter(p[i+1 : j])
		if err != nil {
			return out, err
		}
		out.filter = conds
		out.attr = p[:i]
		if rest := p[j+1:]; rest != "" {
			if !strings.HasPrefix(rest, ".") {
				return out, errors.New("a filter is followed by .attribute or nothing")
			}
			out.sub = rest[1:]
		}
	} else if i := strings.IndexByte(p, '.'); i >= 0 {
		out.attr, out.sub = p[:i], p[i+1:]
	} else {
		out.attr = p
	}
	if out.attr == "" {
		return out, errors.New("a path needs an attribute")
	}
	return out, nil
}

func beforeBracket(s string) string {
	if i := strings.IndexByte(s, '['); i >= 0 {
		return s[:i]
	}
	return s
}

// isSchema is whether s names a schema rather than an attribute in one.
func isSchema(s string) bool {
	last := s[strings.LastIndex(s, ":")+1:]
	return strings.EqualFold(last, "User") || strings.EqualFold(last, "Group")
}

// applyPatch applies ops to res, a resource as a JSON object.
func applyPatch(res map[string]any, ops []patchOp) error {
	for _, op := range ops {
		if err := applyOp(res, op); err != nil {
			return err
		}
	}
	return nil
}

func applyOp(res map[string]any, op patchOp) error {
	if strings.TrimSpace(op.Path) == "" {
		if op.Op == "remove" {
			return badRequest("noTarget", "A remove needs a path.")
		}
		value, ok := op.Value.(map[string]any)
		if !ok {
			return badRequest("invalidValue", "Without a path the value is an object of attributes.")
		}
		for k, v := range value {
			// compat: Entra puts extension attributes in a pathless value as
			// "urn:...:User:department" keys; they are paths.
			if strings.HasPrefix(strings.ToLower(k), "urn:") && !isSchema(k) {
				if err := applyOp(res, patchOp{Op: op.Op, Path: k, Value: v}); err != nil {
					return err
				}
				continue
			}
			if op.Op == "add" {
				addTo(res, k, v)
			} else {
				set(res, k, v)
			}
		}
		return nil
	}
	p, err := parsePath(op.Path)
	if err != nil {
		return badRequest("invalidPath", err.Error())
	}
	container := res
	if p.urn != "" {
		ext, _ := get(res, p.urn).(map[string]any)
		if ext == nil {
			if op.Op == "remove" {
				return nil
			}
			ext = map[string]any{}
			set(res, p.urn, ext)
		}
		container = ext
	}
	if p.filter == nil {
		return applyPlain(container, p, op)
	}
	return applyFiltered(container, p, op)
}

// addTo is add without a filter: values join a multi-valued attribute,
// objects merge, anything else is set.
func addTo(m map[string]any, name string, v any) {
	existing := get(m, name)
	switch cur := existing.(type) {
	case []any:
		for _, el := range asList(v) {
			if !containsValue(cur, el) {
				cur = append(cur, el)
			}
		}
		set(m, name, cur)
	case map[string]any:
		if incoming, ok := v.(map[string]any); ok {
			for k, x := range incoming {
				set(cur, k, x)
			}
			return
		}
		set(m, name, v)
	default:
		set(m, name, v)
	}
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

// containsValue is whether list already holds el, compared by "value" for
// complex elements.
func containsValue(list []any, el any) bool {
	want := elementValue(el)
	for _, x := range list {
		if want != "" && elementValue(x) == want {
			return true
		}
	}
	return false
}

func elementValue(el any) string {
	if m, ok := el.(map[string]any); ok {
		return str(get(m, "value"))
	}
	return str(el)
}

func applyPlain(container map[string]any, p scimPath, op patchOp) error {
	if p.sub == "" {
		switch op.Op {
		case "add":
			addTo(container, p.attr, op.Value)
		case "replace":
			set(container, p.attr, op.Value)
		case "remove":
			// compat: Entra removes group members with a value list rather
			// than a filter.
			if cur, ok := get(container, p.attr).([]any); ok && op.Value != nil {
				drop := asList(op.Value)
				kept := cur[:0:0]
				for _, x := range cur {
					if !containsValue(drop, x) {
						kept = append(kept, x)
					}
				}
				set(container, p.attr, kept)
				return nil
			}
			del(container, p.attr)
		}
		return nil
	}
	parent := get(container, p.attr)
	switch cur := parent.(type) {
	case []any:
		for _, el := range cur {
			if m, ok := el.(map[string]any); ok {
				if op.Op == "remove" {
					del(m, p.sub)
				} else {
					set(m, p.sub, op.Value)
				}
			}
		}
	case map[string]any:
		if op.Op == "remove" {
			del(cur, p.sub)
		} else {
			set(cur, p.sub, op.Value)
		}
	default:
		if op.Op != "remove" {
			set(container, p.attr, map[string]any{p.sub: op.Value})
		}
	}
	return nil
}

func applyFiltered(container map[string]any, p scimPath, op patchOp) error {
	list, _ := get(container, p.attr).([]any)
	matched := false
	var kept []any
	for _, el := range list {
		if !matches(el, p.filter) {
			kept = append(kept, el)
			continue
		}
		matched = true
		m, _ := el.(map[string]any)
		switch {
		case op.Op == "remove" && p.sub == "":
			continue
		case op.Op == "remove":
			del(m, p.sub)
		case p.sub == "":
			if v, ok := op.Value.(map[string]any); ok {
				for k, x := range v {
					set(m, k, x)
				}
			}
		default:
			set(m, p.sub, op.Value)
		}
		kept = append(kept, el)
	}
	if !matched && op.Op != "remove" {
		// compat: Entra replaces emails[type eq "work"].value on someone who
		// has no work email yet; the element is made from the filter.
		el := map[string]any{}
		for _, c := range p.filter {
			el[c.path] = c.value
		}
		if p.sub != "" {
			el[p.sub] = op.Value
		} else if v, ok := op.Value.(map[string]any); ok {
			for k, x := range v {
				el[k] = x
			}
		}
		kept = append(kept, el)
	}
	if kept == nil {
		kept = []any{}
	}
	set(container, p.attr, kept)
	return nil
}

// ---- Users ----------------------------------------------------------------

// userFields is what this service keeps from a user resource.
type userFields struct {
	userName, externalID, email, name string
	active                            *bool
	jobTitle, department, division    string
	manager, employeeType             string
	location, country, city           string
	attributes                        map[string]any
}

// userFieldsOf reads a user resource.
func userFieldsOf(res map[string]any) userFields {
	f := userFields{
		userName: str(get(res, "userName")), externalID: str(get(res, "externalId")),
		jobTitle: str(get(res, "title")), employeeType: str(get(res, "userType")),
		attributes: map[string]any{},
	}
	if b, ok := boolean(get(res, "active")); ok {
		f.active = &b
	}
	f.email = primary(get(res, "emails"), "work")
	if f.email == "" && normalizeEmail(f.userName) != "" {
		f.email = f.userName
	}
	f.email = normalizeEmail(f.email)
	if n, ok := get(res, "name").(map[string]any); ok {
		f.name = str(get(n, "formatted"))
		if f.name == "" {
			f.name = strings.TrimSpace(str(get(n, "givenName")) + " " + str(get(n, "familyName")))
		}
	}
	if f.name == "" {
		f.name = str(get(res, "displayName"))
	}
	if addr := primaryObject(get(res, "addresses"), "work"); addr != nil {
		f.city, f.country = str(get(addr, "locality")), str(get(addr, "country"))
		f.location = str(get(addr, "formatted"))
		if f.location == "" {
			var parts []string
			for _, part := range []string{f.city, str(get(addr, "region")), f.country} {
				if part != "" {
					parts = append(parts, part)
				}
			}
			f.location = strings.Join(parts, ", ")
		}
	}
	for k, v := range res {
		if !strings.HasPrefix(strings.ToLower(k), "urn:") {
			continue
		}
		ext, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(k, schemaEnterprise) {
			f.department, f.division = str(get(ext, "department")), str(get(ext, "division"))
			switch m := get(ext, "manager").(type) {
			case map[string]any:
				f.manager = str(get(m, "displayName"))
				if f.manager == "" {
					f.manager = str(get(m, "value"))
				}
			default:
				f.manager = str(m)
			}
			for from, to := range map[string]string{"employeeNumber": "employee_number", "organization": "organization", "costCenter": "cost_center"} {
				if s := str(get(ext, from)); s != "" {
					f.attributes[to] = s
				}
			}
			continue
		}
		// A custom extension: its simple attributes, by name.
		for name, x := range ext {
			if s := str(x); s != "" {
				f.attributes[name] = s
			}
		}
	}
	return f
}

// primary is the value of the primary element of a multi-valued attribute,
// else the first of kind, else the first.
func primary(v any, kind string) string {
	if m := primaryObject(v, kind); m != nil {
		return str(get(m, "value"))
	}
	return ""
}

func primaryObject(v any, kind string) map[string]any {
	list, _ := v.([]any)
	var first, ofKind map[string]any
	for _, el := range list {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		if b, _ := boolean(get(m, "primary")); b {
			return m
		}
		if first == nil {
			first = m
		}
		if ofKind == nil && strings.EqualFold(str(get(m, "type")), kind) {
			ofKind = m
		}
	}
	if ofKind != nil {
		return ofKind
	}
	return first
}

// mentions is whether ops say anything about attr at the top level.
func mentions(ops []patchOp, attr string) bool {
	for _, op := range ops {
		if strings.EqualFold(strings.TrimSpace(op.Path), attr) {
			return true
		}
		if strings.TrimSpace(op.Path) == "" {
			if m, ok := op.Value.(map[string]any); ok {
				if _, ok := key(m, attr); ok {
					return true
				}
			}
		}
	}
	return false
}

// cloneResource is a deep copy, so a PATCH can be compared with the original.
func cloneResource(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var out map[string]any
	_ = dec.Decode(&out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// ---- Discovery -------------------------------------------------------------

func serviceProviderConfig(location string) map[string]any {
	return map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": scimMaxPage},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []any{map[string]any{
			"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
			"description": "The long-lived token generated on the organization's SCIM settings page.",
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": location},
	}
}

func resourceTypes(base string) []any {
	return []any{
		map[string]any{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":      "User", "name": "User", "endpoint": "/Users", "schema": schemaUser,
			"schemaExtensions": []any{map[string]any{"schema": schemaEnterprise, "required": false}},
			"meta":             map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"},
		},
		map[string]any{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id":      "Group", "name": "Group", "endpoint": "/Groups", "schema": schemaGroup,
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"},
		},
	}
}

func attribute(name, typ string, multi bool, uniqueness string, sub ...map[string]any) map[string]any {
	a := map[string]any{
		"name": name, "type": typ, "multiValued": multi, "required": name == "userName" || name == "displayName",
		"caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": uniqueness,
	}
	if len(sub) > 0 {
		list := make([]any, len(sub))
		for i, s := range sub {
			list[i] = s
		}
		a["subAttributes"] = list
	}
	return a
}

func schemas(base string) []any {
	simple := func(name string) map[string]any { return attribute(name, "string", false, "none") }
	multi := func(name string) map[string]any {
		return attribute(name, "complex", true, "none", simple("value"), simple("type"), attribute("primary", "boolean", false, "none"))
	}
	schema := func(id, name string, attrs ...map[string]any) map[string]any {
		list := make([]any, len(attrs))
		for i, a := range attrs {
			list[i] = a
		}
		return map[string]any{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
			"id":      id, "name": name, "attributes": list,
			"meta": map[string]any{"resourceType": "Schema", "location": base + "/Schemas/" + id},
		}
	}
	return []any{
		schema(schemaUser, "User",
			attribute("userName", "string", false, "server"), simple("externalId"), simple("displayName"), simple("title"), simple("userType"),
			attribute("active", "boolean", false, "none"),
			attribute("name", "complex", false, "none", simple("formatted"), simple("givenName"), simple("familyName")),
			multi("emails"), multi("phoneNumbers"),
			attribute("addresses", "complex", true, "none", simple("type"), simple("formatted"), simple("locality"), simple("region"), simple("country")),
		),
		schema(schemaEnterprise, "EnterpriseUser",
			simple("employeeNumber"), simple("costCenter"), simple("organization"), simple("division"), simple("department"),
			attribute("manager", "complex", false, "none", simple("value"), simple("displayName")),
		),
		schema(schemaGroup, "Group",
			attribute("displayName", "string", false, "server"), simple("externalId"),
			attribute("members", "complex", true, "none", simple("value"), simple("display")),
		),
	}
}

func listResponse(resources []any, total, start int) map[string]any {
	if resources == nil {
		resources = []any{}
	}
	return map[string]any{
		"schemas": []string{schemaList}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(resources), "Resources": resources,
	}
}

// scimPage is startIndex and count, bounded; startIndex counts from 1 and
// stops at what a query offset can hold.
func scimPage(r *http.Request) (start, count int) {
	start, count = 1, 100
	if v, err := strconv.Atoi(r.URL.Query().Get("startIndex")); err == nil && v > 1 {
		start = min(v, math.MaxInt32)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && v >= 0 {
		count = min(v, scimMaxPage)
	}
	return start, count
}
