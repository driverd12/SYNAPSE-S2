import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OperationalScriptTests(unittest.TestCase):
    def test_prep_tomorrow_does_not_seed_demo_memory_by_default(self):
        script = (ROOT / "scripts" / "prep_tomorrow.sh").read_text(encoding="utf-8")

        self.assertNotIn("seed-demo", script)
        self.assertIn('CONTEXT="${SYNAPSE_S2_PREFLIGHT_CONTEXT:-default}"', script)
        self.assertIn("factual preflight evidence", script)


if __name__ == "__main__":
    unittest.main()
