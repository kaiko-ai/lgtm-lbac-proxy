package main

import (
	"net/url"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
)

func ContainsIgnoreCase(s []string, e string) bool {
	for _, v := range s {
		if strings.EqualFold(v, e) {
			return true
		}
	}
	return false
}

func MapKeysToArray[K comparable, V any](tenantLabel map[K]V) []K {
	tenantLabelKeys := make([]K, 0, len(tenantLabel))
	for key := range tenantLabel {
		tenantLabelKeys = append(tenantLabelKeys, key)
	}

	// Sort if keys are strings for deterministic output
	if len(tenantLabelKeys) > 0 {
		if keys, ok := any(tenantLabelKeys).([]string); ok {
			sort.Strings(keys)
			return any(keys).([]K)
		}
	}

	return tenantLabelKeys
}

// ruleToMatcher converts a LabelRule to a prometheus labels.Matcher.
// This is a shared utility function used by both PromQL and LogQL enforcers.
func ruleToMatcher(rule LabelRule) *labels.Matcher {
	var matchType labels.MatchType
	operator := rule.Operator
	value := rule.Values[0]

	// For multiple values, combine with regex OR
	if len(rule.Values) > 1 {
		value = strings.Join(rule.Values, "|")
		if operator == OperatorEquals {
			operator = OperatorRegexMatch
		} else if operator == OperatorNotEquals {
			operator = OperatorRegexNoMatch
		}
	}

	// Map operator to MatchType
	switch operator {
	case OperatorEquals:
		matchType = labels.MatchEqual
	case OperatorNotEquals:
		matchType = labels.MatchNotEqual
	case OperatorRegexMatch:
		matchType = labels.MatchRegexp
	case OperatorRegexNoMatch:
		matchType = labels.MatchNotRegexp
	}

	return &labels.Matcher{
		Name:  rule.Name,
		Type:  matchType,
		Value: value,
	}
}

// singleJoiningSlash joins two URL paths with exactly one slash between them.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// joinURLPath appends the request path to the upstream's base path, keeping
// escaped paths intact. Same behaviour as httputil.NewSingleHostReverseProxy.
func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	apath := a.EscapedPath()
	bpath := b.EscapedPath()
	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}
