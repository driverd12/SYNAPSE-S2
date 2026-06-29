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
        self.assertIn("```math\nZ_i = \\frac{E_i - \\mu_E}{\\sigma_E}\n```", readme)
        self.assertIn("X_t = S_{\\text{in}}W_{\\text{syn}}\\gamma_{\\text{syn}}", readme)
        self.assertIn("\\tilde{U}_{t+1} = \\beta U_t + X_t", readme)
        self.assertIn("W_{ij} \\leftarrow \\operatorname{clip}", readme)
        self.assertIn("\\begin{cases}", readme)

    def test_readme_core_math_section_avoids_inline_dollar_math(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start = readme.index("## **Core Mathematical Formulation**")
        end = readme.index("## **Hardware Integration Optimization**")
        section = readme[start:end]

        self.assertNotIn("$", section)
        self.assertIn("\\operatorname{argTopK}(Z,k)", section)
        self.assertIn("one-cycle discrete form of asymmetric STDP", section)
        self.assertIn("`V_thr`", section)


if __name__ == "__main__":
    unittest.main()
