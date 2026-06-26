import unittest

from event_segmenter import BayesianSurpriseEventSegmenter


class BayesianSurpriseEventSegmenterTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
