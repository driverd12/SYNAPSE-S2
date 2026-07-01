from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    def test_readme_uses_renderer_stable_math_blocks(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertNotIn("\n$$\n", readme)
        self.assertNotIn(r"Z\_i \=", readme)
        self.assertNotIn(r"S\_i \=", readme)
        self.assertNotIn(r"U\[t+1\] \=", readme)
        self.assertNotIn(r"\\Delta w \=", readme)
        self.assertNotIn("\\operatorname", readme)
        self.assertIn("```math\nZ_i = \\frac{E_i - \\mu_E}{\\sigma_E}\n```", readme)
        self.assertIn("X_t = S_{\\text{in}}W_{\\text{syn}}\\gamma_{\\text{syn}}", readme)
        self.assertIn("\\tilde{U}_{t+1} = \\beta U_t + X_t", readme)
        self.assertIn("W_{ij} \\leftarrow \\mathrm{clip}", readme)
        self.assertIn("\\begin{cases}", readme)

    def test_readme_core_math_section_avoids_inline_dollar_math(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = readme.index("## **Core Mathematical Formulation**")
        end = readme.index("## **Hardware Integration Optimization**")
        section = readme[start:end]

        self.assertNotIn("$", section)
        self.assertIn("\\mathrm{argTopK}(Z,k)", section)
        self.assertIn("one-cycle discrete form of asymmetric STDP", section)
        self.assertIn("`V_thr`", section)

    def test_operational_status_docs_are_linked_from_primary_docs(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        compliance = (ROOT / "docs" / "PROPOSAL_COMPLIANCE.md").read_text(encoding="utf-8")
        gap_audit = (ROOT / "docs" / "PRODUCTION_GAP_AUDIT.md").read_text(encoding="utf-8")

        self.assertIn("docs/CURRENT_STATUS.md", readme)
        self.assertIn("scripts/synapse_status_report.py", readme)
        self.assertIn("saved memory namespace selector", readme)
        self.assertIn("Saved memory namespace selector", compliance)
        self.assertIn("Current status report generator", compliance)
        self.assertIn("Cross-process Cortex session closure persistence", compliance)
        self.assertIn("Dashboard context selector was manual-only", gap_audit)
        self.assertIn("The dashboard Memory Context control lists existing namespaces", gap_audit)
        self.assertIn("cross-process Cortex session closures", readme)
        self.assertIn("Closed Cortex sessions could be resurrected", gap_audit)


if __name__ == "__main__":
    unittest.main()
