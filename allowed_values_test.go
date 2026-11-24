package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One anchored regex covering exact names and a prefix, as a policy for a
// team with preview namespaces would use.
func regexPolicy() LabelPolicy {
	return LabelPolicy{Logic: LogicAND, Rules: []LabelRule{
		{Name: "namespace", Operator: "=~", Values: []string{"^(team-a|team-b|team-a-pr-.*)$"}},
	}}
}

func TestAllowedValuesAllows(t *testing.T) {
	a := allowedValuesByLabel(regexPolicy())["namespace"]
	cases := map[string]bool{
		"team-a":                         true,
		"team-b":                         true,
		"team-a-pr-123":                  true,
		"^(team-a|team-b|team-a-pr-.*)$": true, // the policy value itself
		"team-c":                         false,
		"team-a-prx":                     false, // anchored: prefix must be followed by the pattern
		"xteam-a":                        false, // anchored at the start
		"team-a-pr-.*":                   false, // a regex is not checked against a regex
		".*":                             false,
	}
	for v, want := range cases {
		assert.Equal(t, want, a.allows(v), v)
	}

	literal := allowedValuesByLabel(LabelPolicy{Rules: []LabelRule{{Name: "namespace", Operator: "=", Values: []string{"team-.*"}}}})["namespace"]
	assert.False(t, literal.allows("team-a"), "a value of an `=` rule is a literal, not a regex")
}

func TestRegexPolicyAllowsNamedNamespaces(t *testing.T) {
	traceql := TraceQLEnforcer{LabelMap: map[string]string{"namespace": "resource.k8s.namespace.name"}}
	allowed := map[string][]string{
		"logql":   {`{namespace="team-a"}`, `{namespace="team-a-pr-7"}`, `{namespace=~"team-a|team-a-pr-7"}`},
		"promql":  {`up{namespace="team-a"}`, `up{namespace="team-a-pr-7"}`, `up{namespace=~"team-a|team-b"}`},
		"traceql": {`{ resource.k8s.namespace.name = "team-a-pr-7" }`, `{ resource.k8s.namespace.name = "team-b" } | count() > 0`},
	}
	denied := map[string][]string{
		"logql":   {`{namespace="team-c"}`, `{namespace=~"team-a-pr-.*"}`, `{namespace=~".+"}`, `{namespace=~"team-a|team-c"}`},
		"promql":  {`up{namespace="team-c"}`, `up{namespace=~"team-.*"}`},
		"traceql": {`{ resource.k8s.namespace.name = "team-c" }`, `{ resource.k8s.namespace.name =~ "team-.*" }`},
	}
	enforcers := map[string]EnforceQL{"logql": LogQLEnforcer{}, "promql": PromQLEnforcer{}, "traceql": traceql}
	for lang, qs := range allowed {
		for _, q := range qs {
			_, err := enforcers[lang].Enforce(q, regexPolicy())
			require.NoError(t, err, "%s should allow %s", lang, q)
		}
	}
	for lang, qs := range denied {
		for _, q := range qs {
			_, err := enforcers[lang].Enforce(q, regexPolicy())
			require.Error(t, err, "%s should deny %s", lang, q)
		}
	}
}

// A named namespace is still restricted by the injected policy filter.
func TestRegexPolicyStillInjects(t *testing.T) {
	out, err := TraceQLEnforcer{LabelMap: map[string]string{"namespace": "resource.k8s.namespace.name"}}.Enforce(`{ resource.k8s.namespace.name = "team-a-pr-7" }`, regexPolicy())
	require.NoError(t, err)
	assert.Contains(t, out, "^(team-a|team-b|team-a-pr-.*)$")
}
