package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A route without a query word is forwarded unchanged: no parameter added,
// existing ones (like Tempo's tag `scope`) untouched.
func TestEnforceRequestWithoutQueryWordLeavesRequestUnchanged(t *testing.T) {
	policy := &LabelPolicy{Logic: LogicAND, Rules: []LabelRule{{Name: "namespace", Operator: "=", Values: []string{"team-a"}}}}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r, err := http.NewRequest(method, "/api/v2/search/tags?scope=span", nil)
		require.NoError(t, err)
		require.NoError(t, enforceRequest(r, TraceQLEnforcer{}, policy, ""))
		assert.Equal(t, "scope=span", r.URL.RawQuery, method)
	}
}

// Other methods are still refused.
func TestEnforceRequestRejectsOtherMethods(t *testing.T) {
	policy := &LabelPolicy{Logic: LogicAND, Rules: []LabelRule{{Name: "namespace", Operator: "=", Values: []string{"team-a"}}}}
	r, err := http.NewRequest(http.MethodDelete, "/api/v2/search/tags", nil)
	require.NoError(t, err)
	assert.Error(t, enforceRequest(r, TraceQLEnforcer{}, policy, ""))
}
