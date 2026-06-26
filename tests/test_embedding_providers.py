import math
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from embedding_providers import resolve_embedding_provider


def cosine(left, right):
    numerator = sum(float(a) * float(b) for a, b in zip(left, right))
    left_norm = math.sqrt(sum(float(a) * float(a) for a in left))
    right_norm = math.sqrt(sum(float(b) * float(b) for b in right))
    return numerator / max(left_norm * right_norm, 1e-9)


class EmbeddingProviderTests(unittest.TestCase):
    def test_semantic_hash_provider_expands_related_local_compute_terms(self):
        provider = resolve_embedding_provider("semantic-hash")

        left = provider.embed("Metal GPU kernels on Apple Silicon", dimensions=96)
        right = provider.embed("Native MLX acceleration on M-series compute", dimensions=96)
        unrelated = provider.embed("contract renewal budget owner", dimensions=96)

        self.assertEqual(left.provenance["provider"], "semantic-hash-v1")
        self.assertTrue(left.provenance["semantic"])
        self.assertEqual(left.provenance["dimensions"], 96)
        self.assertIn("local_compute", left.provenance["concepts"])
        self.assertGreater(cosine(left.vector, right.vector), 0.35)
        self.assertLess(cosine(left.vector, unrelated.vector), 0.30)

    def test_python_callable_provider_loads_local_encoder_without_cloud_calls(self):
        with TemporaryDirectory() as tmp:
            module_path = Path(tmp) / "local_encoder.py"
            module_path.write_text(
                textwrap.dedent(
                    """
                    def embed(text, dimensions):
                        vector = [0.0] * dimensions
                        vector[0] = 2.0
                        vector[-1] = float(len(text))
                        return {
                            "vector": vector,
                            "model_id": "unit-local-encoder",
                            "semantic": True,
                            "details": {"source": "unit-test"},
                        }
                    """
                ),
                encoding="utf-8",
            )

            provider = resolve_embedding_provider(f"python:{module_path}:embed")
            result = provider.embed("local semantic encoder", dimensions=8)

        self.assertEqual(result.vector[0], 2.0)
        self.assertEqual(result.vector[-1], float(len("local semantic encoder")))
        self.assertEqual(result.provenance["provider"], "python-callable")
        self.assertEqual(result.provenance["model_id"], "unit-local-encoder")
        self.assertTrue(result.provenance["semantic"])
        self.assertTrue(result.provenance["local_only"])
        self.assertEqual(result.provenance["details"], {"source": "unit-test"})

    def test_auto_provider_uses_semantic_hash_as_offline_default(self):
        provider = resolve_embedding_provider("auto")
        result = provider.embed("recall context graph", dimensions=32)

        self.assertEqual(result.provenance["provider"], "semantic-hash-v1")
        self.assertEqual(len(result.vector), 32)
        self.assertTrue(result.provenance["local_only"])


if __name__ == "__main__":
    unittest.main()
