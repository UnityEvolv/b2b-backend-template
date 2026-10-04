package server

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
)

// A startIndex past what a query offset holds is held there, never wrapped
// to a negative offset.
func TestScimPageIsBounded(t *testing.T) {
	for _, tc := range []struct {
		query        string
		start, count int
	}{
		{"", 1, 100},
		{"?startIndex=0&count=-1", 1, 100},
		{"?startIndex=5&count=10", 5, 10},
		{"?count=100000", 1, scimMaxPage},
		{"?startIndex=9223372036854775807", math.MaxInt32, 100},
	} {
		start, count := scimPage(httptest.NewRequest("GET", "/scim/v2/Users"+tc.query, nil))
		if start != tc.start || count != tc.count {
			t.Errorf("%q: got %d, %d; want %d, %d", tc.query, start, count, tc.start, tc.count)
		}
		if int32(start-1) < 0 {
			t.Errorf("%q: offset %d wraps", tc.query, start-1)
		}
	}
}

func resource(t *testing.T, raw string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseFilter(t *testing.T) {
	conds, err := parseFilter(`userName eq "a@b.c" and emails[type eq "work"].value eq "x\"y"`)
	if err != nil || len(conds) != 2 || conds[0].path != "username" || conds[0].value != "a@b.c" ||
		conds[1].path != `emails[type eq "work"].value` || conds[1].value != `x"y` {
		t.Fatalf("%v %v", conds, err)
	}
	if c, err := parseFilter(`active eq true`); err != nil || c[0].value != true {
		t.Errorf("boolean: %v %v", c, err)
	}
	for _, bad := range []string{`userName co "a"`, `userName eq`, `userName eq "a" or id eq "b"`, `userName eq "a`, ``} {
		if _, err := parseFilter(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestApplyPatch(t *testing.T) {
	res := resource(t, `{"userName":"a","emails":[{"value":"a@x","type":"work","primary":true}],"name":{"givenName":"A"}}`)
	ops := []patchOp{
		{Op: "replace", Path: "name.familyName", Value: "Smith"},
		{Op: "add", Path: `phoneNumbers[type eq "mobile"].value`, Value: "123"},
		{Op: "replace", Path: `emails[type eq "work"].value`, Value: "b@x"},
		{Op: "add", Path: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value", Value: "m1"},
		{Op: "add", Value: map[string]any{"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "Ops", "title": "Boss"}},
		{Op: "remove", Path: "name.givenName"},
	}
	if err := applyPatch(res, ops); err != nil {
		t.Fatal(err)
	}
	f := userFieldsOf(res)
	if f.email != "b@x" || f.department != "Ops" || f.manager != "m1" || f.jobTitle != "Boss" || f.name != "Smith" {
		t.Errorf("%+v", f)
	}
	phones := res["phoneNumbers"].([]any)
	if len(phones) != 1 || phones[0].(map[string]any)["value"] != "123" {
		t.Errorf("phones: %v", phones)
	}
	if err := applyPatch(res, []patchOp{{Op: "remove"}}); err == nil {
		t.Error("remove without a path")
	}
}

func TestGroupMemberPatches(t *testing.T) {
	res := resource(t, `{"displayName":"G","members":[{"value":"1"},{"value":"2"}]}`)
	ops := []patchOp{
		{Op: "add", Path: "members", Value: []any{map[string]any{"value": "3"}, map[string]any{"value": "1"}}},
		{Op: "remove", Path: "members", Value: []any{map[string]any{"value": "2"}}},
		{Op: "remove", Path: `members[value eq "3"]`},
		{Op: "replace", Path: "displayName", Value: "H"},
	}
	if err := applyPatch(res, ops); err != nil {
		t.Fatal(err)
	}
	members := res["members"].([]any)
	if len(members) != 1 || elementValue(members[0]) != "1" || res["displayName"] != "H" {
		t.Errorf("%v", res)
	}
}

func TestUserFields(t *testing.T) {
	f := userFieldsOf(resource(t, `{"userName":"A@X.test","active":"False","addresses":[{"type":"work","locality":"Pune","country":"IN"}],
		"urn:acme:custom:2.0:User":{"costCentre":"77"}}`))
	if f.email != "a@x.test" || f.active == nil || *f.active || f.city != "Pune" || f.country != "IN" || f.location != "Pune, IN" || f.attributes["costCentre"] != "77" {
		t.Errorf("%+v", f)
	}
}
