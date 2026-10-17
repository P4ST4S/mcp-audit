package otel

import (
	"github.com/P4ST4S/mcp-audit/internal/audit"
	"testing"
)

func TestSpanTerminalFailures(t *testing.T) {
	for _, outcome := range []audit.Outcome{audit.OutcomeTimeout, audit.OutcomeUpstreamError, audit.OutcomeClientDisconnect, audit.OutcomeMalformedUpstreamResponse, audit.OutcomeCancelled, audit.OutcomeInternalError, audit.OutcomeDenied, audit.OutcomeRateLimited} {
		t.Run(string(outcome), func(t *testing.T) {
			e := &Exporter{}
			span, err := e.spanFromEntry(audit.Entry{Method: "tools/call", Outcome: outcome})
			if err != nil {
				t.Fatal(err)
			}
			if span.Status.Code != statusCodeError || span.Status.Message != string(outcome) {
				t.Fatalf("status=%+v", span.Status)
			}
			assertStringAttr(t, attrMap(span.Attributes), attrErrorType, string(outcome))
		})
	}
}
