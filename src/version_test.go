package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHandleVersion(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/version", nil)
	rec := httptest.NewRecorder()
	handleVersion(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["version"] != appVersion {
		t.Fatalf("version=%q want %q", body["version"], appVersion)
	}
}

func TestHandleVersionMethod(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/version", nil)
	rec := httptest.NewRecorder()
	handleVersion(rec, req)
	if rec.Code != 405 {
		t.Fatalf("status=%d want 405", rec.Code)
	}
}
