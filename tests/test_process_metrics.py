import ctypes
import unittest
from unittest.mock import patch

import process_metrics


class ProcessMemoryTests(unittest.TestCase):
    def test_darwin_reports_current_process_metrics_without_topology_substitution(self):
        def read(pid, flavor, buffer):
            self.assertEqual(flavor, 0)
            record = ctypes.cast(buffer, ctypes.POINTER(process_metrics._RUsageInfoV0)).contents
            record.resident_size = 400_000_000
            record.phys_footprint = 4_300_000_000
            return 0
        with patch.object(process_metrics.sys, "platform", "darwin"), patch.object(
            process_metrics, "_darwin_rusage_function", return_value=read
        ):
            result = process_metrics.observe_process_memory()
        self.assertTrue(result["available"])
        self.assertEqual(result["resident_bytes"], 400_000_000)
        self.assertEqual(result["footprint_bytes"], 4_300_000_000)
        self.assertEqual(result["pid"], process_metrics.os.getpid())

    def test_unavailable_metrics_are_null_and_do_not_break_health(self):
        for result in (-1,):
            with patch.object(process_metrics.sys, "platform", "darwin"), patch.object(
                process_metrics, "_darwin_rusage_function", return_value=lambda *args: result
            ):
                observation = process_metrics.observe_process_memory()
                self.assertFalse(observation["available"])
                self.assertIsNone(observation["resident_bytes"])
                self.assertIsNone(observation["footprint_bytes"])
        with patch.object(process_metrics.sys, "platform", "unsupported"), patch.object(
            process_metrics, "_darwin_rusage_function"
        ) as read:
            self.assertFalse(process_metrics.observe_process_memory()["available"])
            read.assert_not_called()

    def test_darwin_sdk_v0_abi_size(self):
        self.assertEqual(ctypes.sizeof(process_metrics._RUsageInfoV0), 96)
