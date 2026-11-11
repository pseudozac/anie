import unittest
from tools.check_repo import inspect_skill, inspect_workflow


class TestPolicy(unittest.TestCase):
    def test_skill_frontmatter(self):
        good = """---
name: safe-review
description: Use for review.
---
Body
"""
        self.assertEqual(inspect_skill(good, "safe-review"), [])
        self.assertIn("skill name must match folder", inspect_skill(good, "another-name"))

    def test_action_pin(self):
        prefix = """permissions:
  contents: read
jobs:
  example:
    steps:
"""
        good = prefix + "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        self.assertEqual(inspect_workflow(good), [])
        bad = prefix + "      - uses: actions/checkout@v4\n"
        self.assertTrue(any("mutable" in error for error in inspect_workflow(bad)))

    def test_named_steps_are_checked(self):
        good = """permissions:
  contents: read
steps:
  - name: Checkout
    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
        bad = good.replace("@11bd71901bbe5b1630ceea73d27597364c9af683", "@v4")
        self.assertEqual(inspect_workflow(good), [])
        self.assertTrue(any("mutable" in error for error in inspect_workflow(bad)))

    def test_privileged_workflow(self):
        sample = """permissions:
  contents: read
on:
  pull_request_target:
jobs:
  test:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
        self.assertTrue(any("privileged" in error for error in inspect_workflow(sample)))
