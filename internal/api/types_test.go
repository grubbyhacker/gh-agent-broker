package api

import (
	"encoding/json"
	"testing"
)

func TestCIObservationVersionIsSerialized(t *testing.T) {
	observation := CIObservation{Version: CIObservationVersion}
	b, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["version"] != CIObservationVersion {
		t.Fatalf("version=%#v want %q", wire["version"], CIObservationVersion)
	}
}
