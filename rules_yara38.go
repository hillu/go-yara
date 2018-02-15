// +build !yara3.3,!yara3.4,!yara3.5,!yara3.6,!yara3.7

package yara

import (
	"C"
	"fmt"
	"sort"
)

// ByCostDesc is a type used for sorting an slice of Rule by time cost in
// descending order.
type ByCostDesc []Rule

func (r ByCostDesc) Len() int {
	return len(r)
}

func (r ByCostDesc) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r ByCostDesc) Less(i, j int) bool {
	return r[i].cptr.time_cost > r[j].cptr.time_cost
}

// RuleCost contains information about the time cost of a Rule.
type RuleCost struct {
	Rule       Rule
	Cost       uint64
	Percentage float64
}

// GetMostCostlyRules returns the top n rules according to their cost. The cost
// is calculated according to the time spend in matching the rule's strings and
// evaluating its condition. If the same Rules are used for scanning multiple
// files, buffers or processes the costs are accumulated.
func (r *Rules) GetMostCostlyRules(n int) []RuleCost {
	rules := r.GetRules()
	sort.Sort(ByCostDesc(rules))
	result := make([]RuleCost, 0)
	for i, rule := range rules {
		fmt.Println(rule.Identifier())
		if i == n {
			break
		}
		result = append(result, RuleCost{
			Rule:       rule,
			Cost:       uint64(rule.cptr.time_cost),
			Percentage: float64(rule.cptr.time_cost) / float64(r.cptr.time_cost) * 100,
		})
	}
	return result
}
