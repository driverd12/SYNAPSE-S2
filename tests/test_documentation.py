import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DocumentationTests(unittest.TestCase):
    @staticmethod
    def _mcp_tool_names() -> tuple[str, ...]:
        tree = ast.parse((ROOT / "mcp_server.py").read_text(encoding="utf-8"))
        names: list[str] = []
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and decorator.func.attr == "tool"
                ):
                    continue
                explicit_name = None
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                        and isinstance(keyword.value.value, str)
                    ):
                        explicit_name = keyword.value.value
                        break
                if explicit_name is None and decorator.args:
                    first = decorator.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        explicit_name = first.value
                names.append(explicit_name or node.name)
        return tuple(names)

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

    def test_readme_documents_every_implemented_mcp_tool(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        tool_names = self._mcp_tool_names()

        self.assertEqual(len(tool_names), len(set(tool_names)))
        self.assertGreaterEqual(len(tool_names), 70)
        for tool_name in tool_names:
            with self.subTest(tool_name=tool_name):
                self.assertIn(f"`{tool_name}`", readme)

    def test_primary_docs_cover_current_operator_and_release_surfaces(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        status = (ROOT / "docs" / "CURRENT_STATUS.md").read_text(encoding="utf-8")
        gap_audit = (ROOT / "docs" / "PRODUCTION_GAP_AUDIT.md").read_text(encoding="utf-8")
        visual_manual = (
            ROOT / "output" / "manual" / "SYNAPSE-S2_Visual_User_Manual.md"
        ).read_text(encoding="utf-8")

        current_terms = (
            "Impact",
            "Retrieval associations",
            "Memora",
            "image memory",
            "media similarity",
            "LongMemEval",
            "release_update_plan.py",
            "release_provenance.py",
            "release_compatibility.py",
            "release_stage.py",
            "release_environment_evidence.py",
        )
        combined = "\n".join((readme, status, gap_audit, visual_manual))
        for term in current_terms:
            with self.subTest(term=term):
                self.assertTrue(term in combined, msg=f"missing current term: {term}")

        for boundary in (
            "not live merge",
            "promotion_supported: false",
            "not an installer",
        ):
            with self.subTest(boundary=boundary):
                self.assertTrue(
                    boundary in combined,
                    msg=f"missing documented boundary: {boundary}",
                )

    def test_mermaid_blocks_are_closed_and_use_supported_flowcharts(self):
        markdown_paths = [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]
        for path in markdown_paths:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertEqual(text.count("```mermaid"), text.count("```mermaid\n"))
                self.assertEqual(text.count("```"), text.count("```") // 2 * 2)
                for block in text.split("```mermaid\n")[1:]:
                    diagram = block.split("```", 1)[0].lstrip()
                    self.assertTrue(
                        diagram.startswith(("flowchart ", "sequenceDiagram", "stateDiagram")),
                        msg=f"unsupported Mermaid block in {path}",
                    )


if __name__ == "__main__":
    unittest.main()
