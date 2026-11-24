package main

import "regexp"

// allowedValues is the set of label values a policy allows for one label:
// literal values, plus the regexes of `=~` rules.
type allowedValues struct {
	literals map[string]bool
	patterns []*regexp.Regexp
}

// allowedValuesByLabel collects, per label name, the values allowed by every
// rule in the policy (several rules for one label are ORed).
func allowedValuesByLabel(policy LabelPolicy) map[string]*allowedValues {
	byLabel := make(map[string]*allowedValues)
	for _, rule := range policy.Rules {
		a, ok := byLabel[rule.Name]
		if !ok {
			a = &allowedValues{literals: make(map[string]bool)}
			byLabel[rule.Name] = a
		}
		for _, v := range rule.Values {
			// The value itself always counts, so a query repeating a policy
			// value exactly keeps working as before.
			a.literals[v] = true
			if rule.Operator == OperatorRegexMatch {
				// Anchored like Prometheus and Loki label matchers.
				if re, err := regexp.Compile("^(?:" + v + ")$"); err == nil {
					a.patterns = append(a.patterns, re)
				}
			}
		}
	}
	return byLabel
}

// allows reports whether a value requested in a query is within the policy.
// A plain value (no regex characters) is allowed if it is a literal policy
// value or fully matches a policy regex. A value with regex characters must
// equal a policy value exactly: matching one regex's text against another is
// not a subset check (policy `a..` matches the text `a.*`, but `a.*` matches
// far more), so it is not attempted.
func (a *allowedValues) allows(value string) bool {
	if a.literals[value] {
		return true
	}
	if regexp.QuoteMeta(value) != value {
		return false
	}
	for _, re := range a.patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}
