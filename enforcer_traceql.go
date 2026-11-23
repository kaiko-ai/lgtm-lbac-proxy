package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/grafana/tempo/pkg/traceql"
	"github.com/rs/zerolog/log"
)

// TraceQLEnforcer manipulates and enforces tenant isolation on TraceQL queries.
type TraceQLEnforcer struct {
	// LabelMap renames rule names to TraceQL attributes (see TempoConfig.LabelMap).
	LabelMap map[string]string
}

// mapRuleNames returns a copy of policy with each rule name replaced by its
// entry in labelMap, if any. The input policy is not modified.
func mapRuleNames(policy LabelPolicy, labelMap map[string]string) LabelPolicy {
	if len(labelMap) == 0 {
		return policy
	}
	rules := make([]LabelRule, len(policy.Rules))
	for i, rule := range policy.Rules {
		if mapped, ok := labelMap[rule.Name]; ok {
			rule.Name = mapped
		}
		rules[i] = rule
	}
	policy.Rules = rules
	return policy
}

// Enforce modifies a TraceQL query string to enforce multi-label access policy.
// It handles multiple label rules with different operators (=, !=, =~, !~) and logic (AND/OR).
// If the input query is empty, constructs a new query from the policy.
// If the input query is non-empty, validates existing attributes and injects policy filters.
// Returns the modified query or an error if parsing, validation, or modification fails.
func (e TraceQLEnforcer) Enforce(query string, policy LabelPolicy) (string, error) {
	log.Trace().Str("function", "enforce").Str("query", query).Msg("input")

	policy = mapRuleNames(policy, e.LabelMap)

	// Validate policy first
	if err := policy.Validate(); err != nil {
		return "", fmt.Errorf("invalid label policy: %w", err)
	}

	// Handle empty query or just braces
	if query == "" || strings.TrimSpace(query) == "{}" {
		query = buildPolicyQuery(policy)
		log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing empty query")
		return query, nil
	}

	log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing")

	// Parse query to validate syntax
	ast, err := traceql.Parse(query)
	if err != nil {
		return "", fmt.Errorf("invalid TraceQL syntax: %w", err)
	}

	// Check if it's a no-op query (e.g., "{ true }")
	if ast.IsNoop() {
		query = buildPolicyQuery(policy)
		log.Trace().Str("function", "enforce").Str("query", query).Msg("enforcing noop query")
		return query, nil
	}

	// Get serialized version for manipulation
	serialized := ast.String()

	// Validate existing attributes against policy
	if err := validatePolicyAttributes(serialized, policy); err != nil {
		return "", err
	}

	// Check if query already contains all policy attributes
	// Inject the policy into every spanset filter. Always inject, even when the
	// query already names a policy attribute: an attribute in one spanset does
	// not restrict another (e.g. `{ ns = "a" } >> { }`), and ANDing the policy
	// again is harmless.
	filter := buildPolicyFilter(policy)
	modified, injected := injectFilter(serialized, filter)
	if injected == 0 {
		return "", fmt.Errorf("cannot enforce policy: query has no spanset filter")
	}

	// Validate the modified query by re-parsing, and check that every spanset
	// in the result carries the policy. Fail closed: never return a query with
	// an unfiltered spanset.
	reparsed, err := traceql.Parse(modified)
	if err != nil {
		return "", fmt.Errorf("failed to inject policy filter: %w", err)
	}
	modified = reparsed.String()
	if err := verifyEverySpansetFiltered(modified, policy); err != nil {
		return "", err
	}

	log.Trace().Str("function", "enforce").Str("query", modified).Msg("enforced")
	return modified, nil
}

// buildPolicyQuery constructs a minimal TraceQL query from a LabelPolicy.
// Examples:
// - Single rule: { resource.namespace = "prod" }
// - Multiple rules (AND): { resource.namespace = "prod" && resource.team = "backend" }
// - Multiple values: { resource.namespace =~ "prod|staging" }
func buildPolicyQuery(policy LabelPolicy) string {
	filter := buildPolicyFilter(policy)
	return fmt.Sprintf("{ %s }", filter)
}

// buildPolicyFilter creates a filter expression from a LabelPolicy without enclosing braces.
// Handles different operators (=, !=, =~, !~) and logic (AND/OR).
// Examples:
// - resource.namespace = "prod"
// - resource.namespace =~ "prod|staging"
// - resource.namespace = "prod" && resource.team = "backend"
// - resource.namespace = "prod" || resource.team = "backend"
func buildPolicyFilter(policy LabelPolicy) string {
	var filters []string

	for _, rule := range policy.Rules {
		filter := buildRuleFilter(rule)
		filters = append(filters, filter)
	}

	// Combine filters with logic operator
	logicOp := " && "
	if policy.Logic == LogicOR {
		logicOp = " || "
	}

	return strings.Join(filters, logicOp)
}

// buildRuleFilter creates a filter expression for a single LabelRule.
// Handles different operators and multiple values.
// Examples:
// - resource.namespace = "prod"
// - resource.namespace != "test"
// - resource.namespace =~ "prod|staging"
// - resource.team !~ "external|guest"
func buildRuleFilter(rule LabelRule) string {
	operator := rule.Operator

	// For multiple values with = or !=, convert to regex
	if len(rule.Values) > 1 {
		if operator == OperatorEquals {
			operator = OperatorRegexMatch
		} else if operator == OperatorNotEquals {
			operator = OperatorRegexNoMatch
		}
	}

	// Build value expression
	var valueExpr string
	if operator == OperatorRegexMatch || operator == OperatorRegexNoMatch {
		// For regex operators with multiple values, join with |
		if len(rule.Values) > 1 {
			// Escape regex special characters in values
			escapedValues := make([]string, len(rule.Values))
			for i, v := range rule.Values {
				escapedValues[i] = escapeRegexChars(v)
			}
			valueExpr = strconv.Quote(strings.Join(escapedValues, "|"))
		} else {
			// Single value, use as-is (user-provided regex pattern)
			valueExpr = strconv.Quote(rule.Values[0])
		}
	} else {
		// For = and !=, use single value without escaping
		valueExpr = strconv.Quote(rule.Values[0])
	}

	return fmt.Sprintf("%s%s%s", rule.Name, operator, valueExpr)
}

// validatePolicyAttributes validates that any existing policy attributes in the query
// match the allowed values in the policy. Returns error if unauthorized values are found.
func validatePolicyAttributes(query string, policy LabelPolicy) error {
	// Build a map of label name to ALL allowed values across all rules
	// This handles OR logic where multiple rules may allow different values for the same label
	allowedValuesMap := make(map[string]map[string]bool)
	for _, rule := range policy.Rules {
		if _, exists := allowedValuesMap[rule.Name]; !exists {
			allowedValuesMap[rule.Name] = make(map[string]bool)
		}
		for _, v := range rule.Values {
			allowedValuesMap[rule.Name][v] = true
		}
	}

	// Check each label name in the policy
	for labelName, allowedValues := range allowedValuesMap {
		// Pattern to match attribute with value
		// Matches: resource.namespace = "value" or resource.namespace =~ "value1|value2"
		pattern := fmt.Sprintf(`%s\s*=~?\s*[\x60"]([^"\x60]+)[\x60"]`, regexp.QuoteMeta(labelName))
		re := regexp.MustCompile(pattern)

		matches := re.FindAllStringSubmatch(query, -1)
		if len(matches) == 0 {
			// Attribute not found in query, will be injected
			continue
		}

		// Validate all found attribute values
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			value := match[1]

			// Split by pipe for regex patterns
			queryValues := strings.Split(value, "|")
			for _, queryValue := range queryValues {
				queryValue = strings.TrimSpace(queryValue)
				if _, ok := allowedValues[queryValue]; !ok {
					return fmt.Errorf("unauthorized %s: %s", labelName, queryValue)
				}
			}
		}
	}

	return nil
}

// injectFilter ANDs the policy filter into every spanset filter `{ ... }` of a
// serialized TraceQL query, including spansets in pipelines and on either side
// of spanset operators (>>, &&, ||, ...). Braces inside string literals are
// ignored. Both sides are parenthesised so operator precedence can't drop the
// policy (`policy && a || b` would mean `(policy && a) || b`).
// Returns the rewritten query and the number of spansets it changed.
func injectFilter(query string, filter string) (string, int) {
	spans := findSpansets(query)
	if len(spans) == 0 {
		return query, 0
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(query[last:sp[0]])
		inner := strings.TrimSpace(query[sp[0]+1 : sp[1]])
		if inner == "" || inner == "true" {
			fmt.Fprintf(&b, "{ %s }", filter)
		} else {
			fmt.Fprintf(&b, "{ (%s) && (%s) }", filter, inner)
		}
		last = sp[1] + 1
	}
	b.WriteString(query[last:])
	return b.String(), len(spans)
}

// findSpansets returns the [open, close] byte offsets of every top-level
// `{ ... }` in a TraceQL query, skipping braces inside string literals
// ("..." with backslash escapes, or `...`).
func findSpansets(query string) [][2]int {
	var spans [][2]int
	depth, start := 0, -1
	var quote byte
	for i := 0; i < len(query); i++ {
		c := query[i]
		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++ // skip the escaped character
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '`':
			quote = c
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 {
					spans = append(spans, [2]int{start, i})
				}
			}
		}
	}
	return spans
}

// verifyEverySpansetFiltered checks that each spanset filter in a serialized
// query names every policy attribute. It is a last line of defence: a query
// that fails it is rejected rather than sent upstream unfiltered.
func verifyEverySpansetFiltered(query string, policy LabelPolicy) error {
	spans := findSpansets(query)
	if len(spans) == 0 {
		return fmt.Errorf("cannot enforce policy: query has no spanset filter")
	}
	for _, sp := range spans {
		body := query[sp[0] : sp[1]+1]
		for _, rule := range policy.Rules {
			if !strings.Contains(body, rule.Name) {
				return fmt.Errorf("cannot enforce policy: spanset %s is missing %s", body, rule.Name)
			}
		}
	}
	return nil
}

// escapeRegexChars escapes special regex characters in a string to prevent regex injection.
// Escapes: . * + ? [ ] ( ) | ^ $ \
func escapeRegexChars(s string) string {
	// Must escape backslash first to avoid double-escaping
	escaped := strings.ReplaceAll(s, `\`, `\\`)

	// Then escape other special characters
	replacements := map[string]string{
		".": `\.`,
		"*": `\*`,
		"+": `\+`,
		"?": `\?`,
		"[": `\[`,
		"]": `\]`,
		"(": `\(`,
		")": `\)`,
		"|": `\|`,
		"^": `\^`,
		"$": `\$`,
	}
	for char, replacement := range replacements {
		escaped = strings.ReplaceAll(escaped, char, replacement)
	}
	return escaped
}
