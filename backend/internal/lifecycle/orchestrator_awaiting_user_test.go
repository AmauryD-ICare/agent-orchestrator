package lifecycle

import (
	"testing"
	"time"

	"github.com/aoagents/agent-orchestrator/backend/internal/domain"
	"github.com/aoagents/agent-orchestrator/backend/internal/ports"
)

func newAwaitingUserHarness(t *testing.T, kind domain.SessionKind, state domain.ActivityState) (*Manager, *fakeStore, *fakeNotificationSink, time.Time) {
	t.Helper()
	st := newFakeStore()
	sink := &fakeNotificationSink{}
	m := New(st, nil, WithNotificationSink(sink))
	now := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	m.clock = func() time.Time { return now }
	st.sessions["orc-1"] = domain.SessionRecord{
		ID: "orc-1", ProjectID: "mer", Kind: kind, DisplayName: "planner",
		Activity:      domain.Activity{State: state, LastActivityAt: now.Add(-time.Minute)},
		FirstSignalAt: now.Add(-time.Hour),
	}
	return m, st, sink, now
}

func awaitingUserIntents(sink *fakeNotificationSink) []ports.NotificationIntent {
	var out []ports.NotificationIntent
	for _, intent := range sink.intents {
		if intent.Type == domain.NotificationOrchestratorAwaitingUser {
			out = append(out, intent)
		}
	}
	return out
}

func awaitingUserResolutions(sink *fakeNotificationSink) []ports.NotificationResolution {
	var out []ports.NotificationResolution
	for _, res := range sink.resolutions {
		if res.Type == domain.NotificationOrchestratorAwaitingUser {
			out = append(out, res)
		}
	}
	return out
}

func humanPrompt() ports.ActivitySignal {
	return ports.ActivitySignal{
		Valid: true, State: domain.ActivityActive, Event: "user-prompt-submit",
		LatestUserPrompt: "what next?", ConversationCheckpointOrigin: domain.ConversationCheckpointOriginHuman,
	}
}

func coordinationPrompt() ports.ActivitySignal {
	return ports.ActivitySignal{
		Valid: true, State: domain.ActivityActive, Event: "user-prompt-submit",
		ConversationCheckpointOrigin: domain.ConversationCheckpointOriginCoordination,
		CoordinationID:               "report-batch:rpt_1",
	}
}

func turnStop() ports.ActivitySignal {
	return ports.ActivitySignal{Valid: true, State: domain.ActivityIdle, Event: "stop"}
}

// An orchestrator that ends its turn is waiting on the user, whether it asked a
// question or reported results; the user must hear about it.
func TestOrchestratorTurnEndEmitsAwaitingUserNotification(t *testing.T) {
	m, _, sink, now := newAwaitingUserHarness(t, domain.KindOrchestrator, domain.ActivityIdle)

	if err := m.ApplyActivitySignal(ctx, "orc-1", humanPrompt()); err != nil {
		t.Fatal(err)
	}
	if got := awaitingUserIntents(sink); len(got) != 0 {
		t.Fatalf("prompt submit emitted %+v", got)
	}
	if err := m.ApplyActivitySignal(ctx, "orc-1", turnStop()); err != nil {
		t.Fatal(err)
	}
	got := awaitingUserIntents(sink)
	if len(got) != 1 {
		t.Fatalf("awaiting-user intents = %+v, want 1", sink.intents)
	}
	if got[0].SessionID != "orc-1" || got[0].ProjectID != "mer" || got[0].SessionDisplayName != "planner" || !got[0].CreatedAt.Equal(now) {
		t.Fatalf("intent = %+v", got[0])
	}
}

// A worker finishing its turn reports to its orchestrator; it must not page the
// user.
func TestWorkerTurnEndDoesNotEmitAwaitingUserNotification(t *testing.T) {
	m, _, sink, _ := newAwaitingUserHarness(t, domain.KindWorker, domain.ActivityActive)

	if err := m.ApplyActivitySignal(ctx, "orc-1", turnStop()); err != nil {
		t.Fatal(err)
	}
	if len(sink.intents) != 0 {
		t.Fatalf("worker turn end emitted %+v", sink.intents)
	}
}

// Only the end of real work counts: leaving a needs-input pause or exiting is
// not a turn the user has to read.
func TestOrchestratorNonTurnIdleDoesNotEmitAwaitingUserNotification(t *testing.T) {
	for _, tt := range []struct {
		name string
		prev domain.ActivityState
		next domain.ActivityState
	}{
		{name: "waiting_input to idle", prev: domain.ActivityWaitingInput, next: domain.ActivityIdle},
		{name: "active to exited", prev: domain.ActivityActive, next: domain.ActivityExited},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _, sink, _ := newAwaitingUserHarness(t, domain.KindOrchestrator, tt.prev)
			if err := m.ApplyActivitySignal(ctx, "orc-1", ports.ActivitySignal{Valid: true, State: tt.next}); err != nil {
				t.Fatal(err)
			}
			if got := awaitingUserIntents(sink); len(got) != 0 {
				t.Fatalf("emitted %+v", got)
			}
		})
	}
}

// A turn AO started (a report batch) is not the orchestrator answering the
// user, and its prompt is not the user answering the orchestrator: it neither
// pings nor clears an open ping.
func TestOrchestratorCoordinationTurnNeitherNotifiesNorResolves(t *testing.T) {
	m, _, sink, _ := newAwaitingUserHarness(t, domain.KindOrchestrator, domain.ActivityIdle)

	if err := m.ApplyActivitySignal(ctx, "orc-1", coordinationPrompt()); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyActivitySignal(ctx, "orc-1", turnStop()); err != nil {
		t.Fatal(err)
	}
	if got := awaitingUserIntents(sink); len(got) != 0 {
		t.Fatalf("coordination turn emitted %+v", got)
	}
	if got := awaitingUserResolutions(sink); len(got) != 0 {
		t.Fatalf("coordination prompt resolved %+v", got)
	}

	// The next human turn is a reply to the user again.
	if err := m.ApplyActivitySignal(ctx, "orc-1", humanPrompt()); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyActivitySignal(ctx, "orc-1", turnStop()); err != nil {
		t.Fatal(err)
	}
	if got := awaitingUserIntents(sink); len(got) != 1 {
		t.Fatalf("human turn after coordination: intents = %+v, want 1", got)
	}
}

// The user's next prompt is what answers the orchestrator, including a prompt
// queued while an AO-started turn is still running.
func TestOrchestratorHumanPromptResolvesAwaitingUser(t *testing.T) {
	for _, tt := range []struct {
		name string
		prev domain.ActivityState
	}{
		{name: "from idle", prev: domain.ActivityIdle},
		{name: "while active", prev: domain.ActivityActive},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _, sink, now := newAwaitingUserHarness(t, domain.KindOrchestrator, tt.prev)
			if err := m.ApplyActivitySignal(ctx, "orc-1", humanPrompt()); err != nil {
				t.Fatal(err)
			}
			got := awaitingUserResolutions(sink)
			if len(got) != 1 || got[0].SessionID != "orc-1" || !got[0].ResolvedAt.Equal(now) {
				t.Fatalf("resolutions = %+v, want one for orc-1", sink.resolutions)
			}
		})
	}
}

func TestWorkerPromptDoesNotResolveAwaitingUser(t *testing.T) {
	m, _, sink, _ := newAwaitingUserHarness(t, domain.KindWorker, domain.ActivityIdle)
	if err := m.ApplyActivitySignal(ctx, "orc-1", humanPrompt()); err != nil {
		t.Fatal(err)
	}
	if got := awaitingUserResolutions(sink); len(got) != 0 {
		t.Fatalf("worker prompt resolved %+v", got)
	}
}

// Ending the orchestrator leaves nobody waiting on the user.
func TestMarkTerminated_ResolvesOrchestratorAwaitingUser(t *testing.T) {
	m, _, sink, _ := newAwaitingUserHarness(t, domain.KindOrchestrator, domain.ActivityIdle)
	if err := m.MarkTerminated(ctx, "orc-1"); err != nil {
		t.Fatal(err)
	}
	if got := awaitingUserResolutions(sink); len(got) != 1 || got[0].SessionID != "orc-1" {
		t.Fatalf("resolutions = %+v, want one awaiting-user resolution", sink.resolutions)
	}
}
