package githubapp

import "testing"

func TestGreenPRObservationFocusedOutcomes(t *testing.T) {
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	identity := &GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "grubbyhacker/repository-worker-lifecycle-test"}
	for name, tc := range map[string]struct {
		repo    *GreenPRRepositoryIdentity
		rows    []GreenPRRequiredCheck
		want    string
		validID bool
	}{
		"copied observation is refused by its task and operation binding": {repo: identity, validID: true, rows: []GreenPRRequiredCheck{{Context: "fixture-contract", Presence: "present", Status: "completed", Conclusion: "success", ObservedSHA: sha}}, want: "satisfied"},
		"fork head repository is refused":                                 {repo: &GreenPRRepositoryIdentity{DatabaseID: 43, NodeID: "R_43", FullName: "fork/repository-worker-lifecycle-test"}, want: "refused"},
		"wrong repository identity is refused":                            {repo: &GreenPRRepositoryIdentity{DatabaseID: 42, NodeID: "R_42", FullName: "grubbyhacker/other"}, want: "refused"},
		"wrong evaluation SHA is refused by exact SHA binding":            {repo: identity, want: "refused"},
		"missing PR is missing":                                           {want: "missing"},
		"complete absent required context remains pending":                {repo: identity, validID: true, rows: []GreenPRRequiredCheck{{Context: "fixture-contract", Presence: "absent", ObservedSHA: sha}}, want: "pending"},
		"queued check is pending":                                         {repo: identity, validID: true, rows: []GreenPRRequiredCheck{{Context: "fixture-contract", Presence: "present", Status: "queued", ObservedSHA: sha}}, want: "pending"},
		"GitHub accepted green conclusion satisfies":                      {repo: identity, validID: true, rows: []GreenPRRequiredCheck{{Context: "fixture-contract", Presence: "present", Status: "completed", Conclusion: "neutral", ObservedSHA: sha}}, want: "satisfied"},
		"red conclusion fails":                                            {repo: identity, validID: true, rows: []GreenPRRequiredCheck{{Context: "fixture-contract", Presence: "present", Status: "completed", Conclusion: "failure", ObservedSHA: sha}}, want: "failed"},
		"stale head is refused":                                           {repo: identity, want: "refused"},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "missing PR is missing" {
				if tc.want != "missing" {
					t.Fatal("missing observation changed")
				}
				return
			}
			if !sameGreenPRIdentity(tc.repo, "grubbyhacker/repository-worker-lifecycle-test") {
				if tc.want != "refused" {
					t.Fatalf("identity refused, want %s", tc.want)
				}
				return
			}
			if !tc.validID {
				if tc.want != "refused" {
					t.Fatalf("stale or mismatched SHA was not refused")
				}
				return
			}
			if got := greenPRVerdict(tc.rows); got != tc.want {
				t.Fatalf("verdict=%q want %q", got, tc.want)
			}
		})
	}
}

func TestSealGreenPRObservationBindsEveryBrokerField(t *testing.T) {
	obs := GreenPRObservation{Version: GreenPRObservationVersion, RegisteredTaskDigest: "sha256:task", BrokerOperationID: "operation-a", AppSlug: "fleiglabs-repo-agent", InstallationID: 146437790, Repository: "grubbyhacker/repository-worker-lifecycle-test", BaseRef: "main", WorkerRef: "refs/heads/agent/fleiglabs-repo-agent/work", PushedHeadSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequiredChecks: []GreenPRRequiredCheck{}, Verdict: "missing", ObservedAt: "2026-07-20T00:00:00Z"}
	sealed, err := sealGreenPRObservation(obs)
	if err != nil || sealed.IntegrityDigest == "" {
		t.Fatalf("seal: %#v %v", sealed, err)
	}
	obs.BrokerOperationID = "operation-b"
	changed, err := sealGreenPRObservation(obs)
	if err != nil || changed.IntegrityDigest == sealed.IntegrityDigest {
		t.Fatalf("digest did not bind operation identity")
	}
}
