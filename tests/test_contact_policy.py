"""Unit tests for SAGA contact policy matching semantics."""

import unittest

from saga.common.contact_policy import (
    aid_specificity,
    check_aid,
    check_rulebook,
    match,
)


class ContactPolicyTests(unittest.TestCase):
    """Cover the minimum contact policy semantics required by the worklog."""

    def test_check_aid_accepts_well_formed_aid(self) -> None:
        """A valid AID should pass format validation."""
        self.assertTrue(check_aid("alice@example.com:calendar_agent"))

    def test_check_aid_rejects_missing_separator(self) -> None:
        """An invalid AID should fail format validation."""
        self.assertFalse(check_aid("alice@example.com"))

    def test_check_rulebook_rejects_budget_below_minus_one(self) -> None:
        """A budget below -1 is outside the accepted policy range."""
        rulebook = [{"pattern": "*", "budget": -2}]
        self.assertFalse(check_rulebook(rulebook))

    def test_aid_specificity_ranks_specific_rules_above_wildcards(self) -> None:
        """Specific patterns must outrank generic wildcards."""
        wildcard = aid_specificity("*")
        domain_rule = aid_specificity("*@company.com:*")
        exact_rule = aid_specificity("alice@company.com:calendar_agent")
        self.assertLess(wildcard, domain_rule)
        self.assertLess(domain_rule, exact_rule)

    def test_match_returns_most_specific_rule_budget(self) -> None:
        """The most specific matching rule should determine the budget."""
        rulebook = [
            {"pattern": "*", "budget": 100},
            {"pattern": "*@company.com:*", "budget": 10},
            {"pattern": "alice@company.com:calendar_agent", "budget": 3},
        ]
        self.assertEqual(match(rulebook, "alice@company.com:calendar_agent"), 3)

    def test_match_keeps_first_match_on_equal_specificity(self) -> None:
        """If specificity ties, the first matching rule should win."""
        rulebook = [
            {"pattern": "alice@company.com:calendar_agent", "budget": 7},
            {"pattern": "alice@company.com:calendar_agent", "budget": 2},
        ]
        self.assertEqual(match(rulebook, "alice@company.com:calendar_agent"), 7)

    def test_match_supports_blocklist_budget(self) -> None:
        """A blocking rule should be able to deny access with budget -1."""
        rulebook = [
            {"pattern": "*", "budget": 10},
            {"pattern": "mallory@evil.com:*", "budget": -1},
        ]
        self.assertEqual(match(rulebook, "mallory@evil.com:attacker"), -1)

    def test_match_returns_zero_when_nothing_matches(self) -> None:
        """Without a matching rule, the default budget remains zero."""
        rulebook = [{"pattern": "alice@example.com:calendar_agent", "budget": 1}]
        self.assertEqual(match(rulebook, "bob@example.com:calendar_agent"), 0)

    def test_match_rejects_bad_aid_format(self) -> None:
        """Badly formatted AIDs should return the explicit format error code."""
        self.assertEqual(match([{"pattern": "*", "budget": 1}], "bad-aid"), -2)


if __name__ == "__main__":
    unittest.main()
