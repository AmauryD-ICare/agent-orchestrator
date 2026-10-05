package session

import (
	"context"
	"errors"
	"testing"

	"github.com/aoagents/agent-orchestrator/backend/internal/domain"
	"github.com/aoagents/agent-orchestrator/backend/internal/ports"
)

// SSH transport ports never identify the web/API authority, so an SSH origin on
// a custom port resolves to the provider host without that port.
func TestClaimPRSSHPortDropped(t *testing.T) {
	st := newFakeStore()
	st.sessions["demo-1"] = domain.SessionRecord{ID: "demo-1", ProjectID: "demo", Kind: domain.KindWorker, Metadata: domain.SessionMetadata{WorkspacePath: "/ws"}}
	st.projects["demo"] = domain.ProjectRecord{ID: "demo", RepoOriginURL: "ssh://git@gitlab.example.com:8443/alice/repo.git"}
	scm := &claimTargetSCM{}
	svc := NewWithDeps(Deps{Store: st, SCM: scm, PRClaimer: &fakePRClaimer{}})
	_, err := svc.ClaimPR(context.Background(), "demo-1", "7", ClaimPROptions{})
	if err != nil {
		t.Fatal(err)
	}
	if scm.refs[0].Repo.Host != "gitlab.example.com" {
		t.Fatalf("claim SCM authority = %q; SSH port must not leak into the provider host", scm.refs[0].Repo.Host)
	}
}
func TestClaimPRSelfManagedGitLabSSHPortOrigin(t *testing.T) {
	const origin = "ssh://git@gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway.git"
	const mr = "https://gitlab.icareweb.com/production_software/new-pogo-multi-gateway/-/merge_requests/32"
	for _, tc := range []struct {
		name, origin, ref string
		wantErr           error
	}{
		{"ssh URL with port", origin, mr, nil},
		{"ssh URL with port numeric ref", origin, "32", nil},
		{"scp-style origin", "git@gitlab.icareweb.com:production_software/new-pogo-multi-gateway.git", mr, nil},
		{"different host", "ssh://git@gitlab.other.com:2200/production_software/new-pogo-multi-gateway.git", mr, ErrProjectMismatch},
		{"HTTPS port is not ignored", "https://gitlab.icareweb.com:2200/production_software/new-pogo-multi-gateway.git", mr, ErrProjectMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			st.sessions["demo-1"] = domain.SessionRecord{ID: "demo-1", ProjectID: "demo", Kind: domain.KindWorker, Metadata: domain.SessionMetadata{WorkspacePath: "/ws"}}
			st.projects["demo"] = domain.ProjectRecord{ID: "demo", RepoOriginURL: tc.origin}
			scm, claimer := &claimTargetSCM{}, &fakePRClaimer{}
			svc := NewWithDeps(Deps{Store: st, SCM: scm, PRClaimer: claimer})
			_, err := svc.ClaimPR(context.Background(), "demo-1", tc.ref, ClaimPROptions{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				if len(scm.refs) != 0 || claimer.called {
					t.Fatal("rejected claim reached SCM or storage")
				}
				return
			}
			if len(scm.refs) != 1 || scm.refs[0].URL != mr || scm.refs[0].Repo.Host != "gitlab.icareweb.com" {
				t.Fatalf("SCM target = %+v", scm.refs)
			}
			if !claimer.called || claimer.gotPR.URL != mr || claimer.gotPR.Repo != "production_software/new-pogo-multi-gateway" {
				t.Fatalf("persisted claim = %+v", claimer.gotPR)
			}
		})
	}
}

func TestClaimPRHTTPSPortOriginStillClaimable(t *testing.T) {
	st := newFakeStore()
	st.sessions["demo-1"] = domain.SessionRecord{ID: "demo-1", ProjectID: "demo", Kind: domain.KindWorker, Metadata: domain.SessionMetadata{WorkspacePath: "/ws"}}
	st.projects["demo"] = domain.ProjectRecord{ID: "demo", RepoOriginURL: "https://gitlab.example.com:8443/alice/repo.git"}
	svc := NewWithDeps(Deps{Store: st, SCM: &claimTargetSCM{}, PRClaimer: &fakePRClaimer{}})
	_, err := svc.ClaimPR(context.Background(), "demo-1", "7", ClaimPROptions{})
	if err != nil {
		t.Fatalf("previously supported HTTPS origin is no longer claimable: %v", err)
	}
}

func TestClaimPRReviewCompletenessFollowsReviewFetch(t *testing.T) {
	newDeps := func(scm fakeSCM, claimer *fakePRClaimer) Deps {
		st := newFakeStore()
		st.sessions["demo-1"] = domain.SessionRecord{ID: "demo-1", ProjectID: "demo", Kind: domain.KindWorker, Metadata: domain.SessionMetadata{WorkspacePath: "/ws"}}
		st.projects["demo"] = domain.ProjectRecord{ID: "demo", RepoOriginURL: "https://github.com/acme/repo"}
		return Deps{Store: st, SCM: scm, PRClaimer: claimer}
	}
	obs := ports.SCMObservation{
		Fetched: true, Provider: "github", Host: "github.com", Repo: "acme/repo",
		PR: ports.SCMPRObservation{URL: "https://github.com/acme/repo/pull/7", Number: 7},
	}

	t.Run("partial fetch claims partial certainty", func(t *testing.T) {
		claimer := &fakePRClaimer{}
		scm := fakeSCM{obs: obs, review: ports.SCMReviewObservation{Partial: true}}
		svc := NewWithDeps(newDeps(scm, claimer))
		if _, err := svc.ClaimPR(context.Background(), "demo-1", "7", ClaimPROptions{}); err != nil {
			t.Fatal(err)
		}
		if claimer.gotMode != ports.ReviewWriteMerge {
			t.Fatalf("mode = %v, want merge", claimer.gotMode)
		}
		if !claimer.gotPR.ReviewPartial || claimer.gotPR.ReviewObservedAt.IsZero() {
			t.Fatalf("partial claim must store (observed, partial=true), got (%v, %t)",
				claimer.gotPR.ReviewObservedAt, claimer.gotPR.ReviewPartial)
		}
	})

	t.Run("full fetch claims exact certainty", func(t *testing.T) {
		claimer := &fakePRClaimer{}
		scm := fakeSCM{obs: obs, review: ports.SCMReviewObservation{}}
		svc := NewWithDeps(newDeps(scm, claimer))
		if _, err := svc.ClaimPR(context.Background(), "demo-1", "7", ClaimPROptions{}); err != nil {
			t.Fatal(err)
		}
		if claimer.gotMode != ports.ReviewWriteReplace {
			t.Fatalf("mode = %v, want replace", claimer.gotMode)
		}
		if claimer.gotPR.ReviewPartial || claimer.gotPR.ReviewObservedAt.IsZero() {
			t.Fatalf("full claim must store (observed, partial=false), got (%v, %t)",
				claimer.gotPR.ReviewObservedAt, claimer.gotPR.ReviewPartial)
		}
	})

	t.Run("failed review fetch offers no certainty", func(t *testing.T) {
		claimer := &fakePRClaimer{}
		scm := fakeSCM{obs: obs, reviewErr: errors.New("review window unavailable")}
		svc := NewWithDeps(newDeps(scm, claimer))
		if _, err := svc.ClaimPR(context.Background(), "demo-1", "7", ClaimPROptions{}); err != nil {
			t.Fatal(err)
		}
		if claimer.gotMode != ports.ReviewWritePreserve {
			t.Fatalf("mode = %v, want preserve", claimer.gotMode)
		}
		if !claimer.gotPR.ReviewObservedAt.IsZero() || claimer.gotPR.ReviewPartial {
			t.Fatalf("claim with failed review fetch must pass the zero pair so the upsert keeps stored certainty, got (%v, %t)",
				claimer.gotPR.ReviewObservedAt, claimer.gotPR.ReviewPartial)
		}
	})
}
