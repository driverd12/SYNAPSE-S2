import math
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import embedding_providers
from embedding_providers import EmbeddingProviderError, resolve_embedding_provider


def cosine(left, right):
    numerator = sum(float(a) * float(b) for a, b in zip(left, right))
    left_norm = math.sqrt(sum(float(a) * float(a) for a in left))
    right_norm = math.sqrt(sum(float(b) * float(b) for b in right))
    return numerator / max(left_norm * right_norm, 1e-9)


class EmbeddingProviderTests(unittest.TestCase):
    def _neural_provider_class(self):
        self.assertTrue(
            hasattr(embedding_providers, "MLXNeuralEmbeddingProvider"),
            "MLXNeuralEmbeddingProvider must be implemented",
        )
        return embedding_providers.MLXNeuralEmbeddingProvider

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

    def test_mlx_neural_provider_resolves_without_eager_model_load(self):
        try:
            provider = resolve_embedding_provider("mlx-neural:unit-neural-model")
        except EmbeddingProviderError as exc:
            self.fail(
                "resolver must support mlx-neural providers without eager model load: "
                f"{exc}"
            )

        self.assertEqual(provider.provider_id, "mlx-neural-v1")
        self.assertEqual(getattr(provider, "model_id", None), "unit-neural-model")
        self.assertIsNone(getattr(provider, "_runtime", None))

    def test_mlx_neural_provider_info_does_not_eager_load_model(self):
        Provider = self._neural_provider_class()
        loaded = []
        provider = Provider(
            model_id="unit-neural-model",
            runtime_factory=lambda config: loaded.append(config),
        )

        self.assertTrue(hasattr(provider, "info"), "provider must expose lazy info()")
        info = provider.info(dimensions=32)

        self.assertEqual(loaded, [])
        self.assertEqual(info["provider"], "mlx-neural-v1")
        self.assertEqual(info["provider_type"], "mlx-neural")
        self.assertEqual(info["model_id"], "unit-neural-model")
        self.assertEqual(info["dimensions"], 32)
        self.assertTrue(info["semantic"])
        self.assertTrue(info["local_only"])

    def test_mlx_neural_provider_projects_runtime_embedding_with_provenance(self):
        Provider = self._neural_provider_class()
        loaded = []

        class FakeRuntime:
            model_id = "unit-neural-model"
            native_mlx = True

            def embed_text(self, text, *, pooling, max_tokens):
                loaded.append((text, pooling, max_tokens))
                return [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]

        provider = Provider(
            model_id="unit-neural-model",
            runtime_factory=lambda config: FakeRuntime(),
            pooling="mean",
            max_tokens=128,
        )

        result = provider.embed("neural semantic recall", dimensions=10)

        self.assertEqual(loaded, [("neural semantic recall", "mean", 128)])
        self.assertEqual(len(result.vector), 10)
        self.assertAlmostEqual(
            math.sqrt(sum(value * value for value in result.vector)),
            1.0,
            places=6,
        )
        self.assertEqual(result.provenance["provider"], "mlx-neural-v1")
        self.assertEqual(result.provenance["provider_type"], "mlx-neural")
        self.assertEqual(result.provenance["model_id"], "unit-neural-model")
        self.assertTrue(result.provenance["semantic"])
        self.assertTrue(result.provenance["local_only"])
        self.assertTrue(result.provenance["native_mlx"])
        self.assertEqual(result.provenance["pooling"], "mean")
        self.assertEqual(result.provenance["source_dimensions"], 6)

    def test_mlx_neural_provider_wraps_dependency_failure_with_actionable_message(self):
        Provider = self._neural_provider_class()

        def broken_runtime(_config):
            raise ImportError("No module named 'mlx_lm'")

        provider = Provider(
            model_id="unit-neural-model",
            runtime_factory=broken_runtime,
        )

        with self.assertRaisesRegex(
            EmbeddingProviderError,
            "mlx-lm.*SYNAPSE_S2_NEURAL_MODEL",
        ):
            provider.embed("dependency failure path", dimensions=8)

    def test_mlx_neural_runtime_falls_back_to_existing_cache_snapshot(self):
        Runtime = embedding_providers.MLXNeuralEmbeddingRuntime

        with TemporaryDirectory() as tmp:
            cache_root = Path(tmp)
            snapshot = (
                cache_root
                / "models--unit--fallback-model"
                / "snapshots"
                / "abc123"
            )
            snapshot.mkdir(parents=True)

            fake_hub = type(sys)("huggingface_hub")

            def broken_snapshot_download(**_kwargs):
                raise BrokenPipeError("broken pipe")

            fake_hub.snapshot_download = broken_snapshot_download
            previous_hub = sys.modules.get("huggingface_hub")
            sys.modules["huggingface_hub"] = fake_hub
            runtime = object.__new__(Runtime)
            runtime.source = "unit/fallback-model"
            runtime.cache_fallback_used = False
            try:
                resolved = runtime._resolve_model_ref(
                    embedding_providers.MLXNeuralEmbeddingConfig(
                        model_id="unit/fallback-model",
                        cache_dir=str(cache_root),
                        revision=None,
                        pooling="mean",
                        max_tokens=512,
                        normalize=True,
                        local_files_only=False,
                    )
                )
            finally:
                if previous_hub is None:
                    sys.modules.pop("huggingface_hub", None)
                else:
                    sys.modules["huggingface_hub"] = previous_hub

        self.assertEqual(Path(resolved), snapshot)
        self.assertEqual(runtime.source, str(snapshot))
        self.assertTrue(runtime.cache_fallback_used)


if __name__ == "__main__":
    unittest.main()
