import unittest
from tools.check_repo import inspect_skill, inspect_workflow


class TestPolicy(unittest.TestCase):
    def test_skill_frontmatter(self):
        good = "---\nname: safe-review\ndescription: Use for review.\n---\nBody\n"
        self.assertEqual(inspect_skill(good, "safe-review"), [])
        self.assertIn("skill name must match folder", inspect_skill(good, "another-name"))

    def test_action_pin(self):
        prefix = "permissions:\n  contents: read\njobs:\n  example:\n    steps:\n"
        good = prefix + "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        self.assertEqual(inspect_workflow(good), [])
        bad = prefix + "      - uses: actions/checkout@v4\n"
        self.assertTrue(any("mutable" in e for e in inspect_workflow(bad)))

    def test_privileged_workflow(self):
        prefix = "permissions:\n  contents: read\non:\n  pull_request_target:\n"
        body = "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        self.assertTrue(any("privileged" in e for e in inspect_workflow(prefix + body)))
