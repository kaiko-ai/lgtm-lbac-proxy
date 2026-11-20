package main

import (
	"strings"
	"testing"

	"github.com/grafana/tempo/pkg/traceql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every spanset in an enforced query must carry the policy, whatever the
// query shape. Before the fix, pipelines, spanset operators and queries that
// already named a policy attribute came back unfiltered.
func TestTraceQLEnforcer_FiltersEverySpanset(t *testing.T) {
	policy := LabelPolicy{
		Logic: LogicAND,
		Rules: []LabelRule{{Name: "resource.k8s.namespace.name", Operator: "=~", Values: []string{"^(team-a|team-a-pr-.*)$"}}},
	}
	queries := map[string]string{
		"pipeline count":            `{ } | count() > 0`,
		"pipeline select":           `{ true } | select(span.http.url)`,
		"pipeline aggregate":        `{ span.http.status_code = 500 } | avg(duration) > 1s`,
		"metrics":                   `{ resource.service.name = "a" } | rate()`,
		"descendant":                `{ resource.service.name = "a" } >> { resource.service.name = "b" }`,
		"spanset and":               `{ resource.service.name = "a" } && { resource.service.name = "b" }`,
		"spanset or":                `{ resource.service.name = "a" } || { resource.service.name = "b" }`,
		"or inside a spanset":       `{ resource.service.name = "a" || span.http.status_code = 500 }`,
		"pipeline then spanset":     `{ resource.service.name = "a" } | by(span.http.method) | { span.http.status_code = 500 }`,
		"braces in a string":        `{ span.message = "x{y}z" } | count() > 0`,
		"second spanset unfiltered": `{ span.http.method = "GET" } >> { }`,
	}
	for name, q := range queries {
		t.Run(name, func(t *testing.T) {
			out, err := TraceQLEnforcer{}.Enforce(q, policy)
			require.NoError(t, err)
			_, err = traceql.Parse(out)
			require.NoError(t, err, "enforced query must be valid TraceQL: %s", out)

			spans := findSpansets(out)
			require.NotEmpty(t, spans, out)
			for _, sp := range spans {
				assert.Contains(t, out[sp[0]:sp[1]+1], "resource.k8s.namespace.name", "unfiltered spanset in %s", out)
			}
		})
	}
}

// A string literal containing braces is not a spanset.
func TestFindSpansetsSkipsStrings(t *testing.T) {
	q := "{ span.message = `a{b}c` && span.other = \"d}e\" } | count() > 0"
	assert.Len(t, findSpansets(q), 1)
}

// The final check rejects a query with an unfiltered spanset instead of
// sending it upstream.
func TestVerifyEverySpansetFilteredFailsClosed(t *testing.T) {
	policy := LabelPolicy{Logic: LogicAND, Rules: []LabelRule{{Name: "resource.namespace", Operator: "=", Values: []string{"prod"}}}}
	err := verifyEverySpansetFiltered("({ resource.namespace = `prod` }) >> ({ true })", policy)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "missing resource.namespace"))
}
