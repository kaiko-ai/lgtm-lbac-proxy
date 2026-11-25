package main

import (
	"regexp"
	"testing"

	"github.com/grafana/tempo/pkg/traceql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var namespaceMap = map[string]string{"namespace": "resource.k8s.namespace.name"}

// A bare `namespace` attribute in a filter, i.e. not part of a longer name.
var bareNamespace = regexp.MustCompile(`(^|[^.\w])namespace\s*(=|!=|=~|!~)`)

func namespacePolicy(values ...string) LabelPolicy {
	return LabelPolicy{Logic: LogicAND, Rules: []LabelRule{{Name: "namespace", Operator: "=", Values: values}}}
}

// With the map, a `namespace` rule written for Loki and Prometheus filters
// traces on the resource attribute, in every spanset.
func TestTraceQLEnforcer_LabelMapFiltersEverySpanset(t *testing.T) {
	enforcer := TraceQLEnforcer{LabelMap: namespaceMap}
	policy := namespacePolicy("team-a", "team-b")
	queries := map[string]string{
		"empty":                     ``,
		"noop":                      `{ true }`,
		"simple":                    `{ resource.service.name = "a" }`,
		"pipeline":                  `{ } | count() > 0`,
		"descendant":                `{ resource.service.name = "a" } >> { resource.service.name = "b" }`,
		"spanset or":                `{ resource.service.name = "a" } || { resource.service.name = "b" }`,
		"second spanset unfiltered": `{ span.http.method = "GET" } >> { }`,
	}
	for name, q := range queries {
		t.Run(name, func(t *testing.T) {
			out, err := enforcer.Enforce(q, policy)
			require.NoError(t, err)
			_, err = traceql.Parse(out)
			require.NoError(t, err, "enforced query must be valid TraceQL: %s", out)
			assert.NotRegexp(t, bareNamespace, out, "rule name must be mapped: %s", out)

			spans := findSpansets(out)
			require.NotEmpty(t, spans, out)
			for _, sp := range spans {
				span := out[sp[0] : sp[1]+1]
				assert.Contains(t, span, "resource.k8s.namespace.name", "unfiltered spanset in %s", out)
				assert.Contains(t, span, "team-a", out)
				assert.Contains(t, span, "team-b", out)
			}
		})
	}
}

// A query naming a namespace outside the policy is rejected, as without the
// map: the check runs against the mapped attribute name.
func TestTraceQLEnforcer_LabelMapOtherNamespace(t *testing.T) {
	enforcer := TraceQLEnforcer{LabelMap: namespaceMap}
	_, err := enforcer.Enforce(`{ resource.k8s.namespace.name = "team-z" }`, namespacePolicy("team-a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "team-z")
}

// Rules not in the map keep their name, and without a map nothing changes.
func TestTraceQLEnforcer_LabelMapLeavesOtherRules(t *testing.T) {
	policy := LabelPolicy{Logic: LogicAND, Rules: []LabelRule{
		{Name: "namespace", Operator: "=", Values: []string{"team-a"}},
		{Name: "resource.team", Operator: "=", Values: []string{"foundry"}},
	}}
	out, err := TraceQLEnforcer{LabelMap: namespaceMap}.Enforce(``, policy)
	require.NoError(t, err)
	assert.Contains(t, out, "resource.k8s.namespace.name")
	assert.Contains(t, out, "resource.team")

	out, err = TraceQLEnforcer{}.Enforce(``, namespacePolicy("team-a"))
	require.NoError(t, err)
	assert.Regexp(t, bareNamespace, out)
}

// The caller's policy is shared across upstreams and must not be modified.
func TestMapRuleNamesDoesNotModifyInput(t *testing.T) {
	policy := namespacePolicy("team-a")
	mapped := mapRuleNames(policy, namespaceMap)
	assert.Equal(t, "namespace", policy.Rules[0].Name)
	assert.Equal(t, "resource.k8s.namespace.name", mapped.Rules[0].Name)
}
