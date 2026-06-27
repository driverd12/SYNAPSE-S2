import unittest

from event_segmenter import BayesianSurpriseEventSegmenter


class BayesianSurpriseEventSegmenterTests(unittest.TestCase):
    def test_embedding_surprise_keeps_semantic_paraphrases_together(self):
        def fake_embedder(sentence: str) -> list[float]:
            lowered = sentence.lower()
            if any(token in lowered for token in ("metal", "m-series", "gpu", "compute")):
                return [1.0, 0.0, 0.0]
            if any(token in lowered for token in ("contract", "renewal", "approval")):
                return [0.0, 1.0, 0.0]
            return [0.0, 0.0, 1.0]

        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=0.40,
            min_segment_sentences=1,
            embedding_fn=fake_embedder,
        )
        text = (
            "Metal compiles local kernels for M-series acceleration. "
            "On-chip GPU execution keeps native compute efficient. "
            "Contract renewal approvals need finance owner review."
        )

        segments = segmenter.segment(
            text,
            context_id="default",
            source_tag="semantic-brief",
        )

        self.assertEqual(len(segments), 2)
        self.assertEqual(segments[0]["sentence_count"], 2)
        self.assertEqual(segments[0]["surprise_mode"], "embedding")
        self.assertLess(segments[0]["semantic_surprise_score"], 0.05)
        self.assertGreaterEqual(segments[1]["semantic_surprise_score"], 0.9)

    def test_segments_text_when_topic_surprise_crosses_threshold(self):
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=0.58,
            min_segment_sentences=1,
        )
        text = (
            "Apple Silicon MLX compiles spiking neural kernels into Metal. "
            "The local SNN tracks sparse top-k spike populations for recall. "
            "Procurement then reviews supplier budget exposure and contract risk. "
            "Finance needs renewal timing, approval owners, and payment status."
        )

        segments = segmenter.segment(
            text,
            context_id="board-demo",
            source_tag="morning-brief",
        )

        self.assertGreaterEqual(len(segments), 2)
        self.assertEqual(segments[0]["tag"], "morning-brief-event-001")
        self.assertIn("apple", segments[0]["keywords"])
        self.assertTrue(
            any("procurement" in segment["keywords"] for segment in segments)
        )
        self.assertTrue(
            any(float(segment["surprise_score"]) >= 0.58 for segment in segments[1:])
        )

    def test_segmenter_is_deterministic_for_same_input(self):
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=0.50,
            min_segment_sentences=1,
        )
        text = (
            "Codex stores local context. "
            "Codex recalls local context. "
            "Thermal telemetry changes the operating envelope."
        )

        first = segmenter.segment(text, context_id="demo", source_tag="deterministic")
        second = segmenter.segment(text, context_id="demo", source_tag="deterministic")

        self.assertEqual(first, second)

    def test_preserves_urls_ips_and_versions_inside_sentences(self):
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=0.50,
            min_segment_sentences=1,
        )
        text = (
            "The dashboard runs at http://127.0.0.1:8765 and uses S2 Core v2.3.1. "
            "Restart Codex and Claude clients after MCP config updates."
        )

        segments = segmenter.segment(
            text,
            context_id="default",
            source_tag="endpoint-brief",
        )

        rendered = " ".join(segment["text"] for segment in segments)
        self.assertIn("http://127.0.0.1:8765", rendered)
        self.assertIn("v2.3.1", rendered)
        self.assertFalse(any(segment["text"] == "0. 0." for segment in segments))
        self.assertEqual(
            sum("http://127.0.0.1:8765" in segment["text"] for segment in segments),
            1,
        )

    def test_preserves_local_dot_paths_inside_sentences(self):
        segmenter = BayesianSurpriseEventSegmenter(
            surprise_threshold=0.50,
            min_segment_sentences=1,
        )
        text = (
            "The sidecar watches .synapse_s2/capture_inbox for local payloads. "
            "It moves processed files into .synapse_s2/capture_processed."
        )

        segments = segmenter.segment(
            text,
            context_id="default",
            source_tag="path-brief",
        )

        rendered = " ".join(segment["text"] for segment in segments)
        self.assertIn(".synapse_s2/capture_inbox", rendered)
        self.assertIn(".synapse_s2/capture_processed", rendered)
        self.assertFalse(any(segment["text"] == "The sidecar watches ." for segment in segments))


if __name__ == "__main__":
    unittest.main()
