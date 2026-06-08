"""Boundary-value tests for Shamir STEP/RECT/MASK behavior."""

from __future__ import annotations

import unittest

from neural import MASK, RECT13, STEP13


class BoundaryValueTests(unittest.TestCase):
    """Verify edge behavior around the 1/3 and 2/3 thresholds."""

    def setUp(self) -> None:
        """Create fixed Shamir layers for each test."""
        self.step = STEP13()
        self.rect = RECT13()
        self.mask = MASK()

    def test_step_respects_threshold_endpoints(self) -> None:
        """The exact threshold points should map to hard safe outputs."""
        self.assertEqual(self.step(1.0 / 3.0), 0.0)
        self.assertEqual(self.step(2.0 / 3.0), 1.0)

    def test_rect_is_positive_inside_unsafe_interval(self) -> None:
        """Values just inside the unsafe interval should trigger RECT."""
        self.assertGreater(self.rect((1.0 / 3.0) + 1e-6), 0.0)
        self.assertGreater(self.rect((2.0 / 3.0) - 1e-6), 0.0)

    def test_mask_is_positive_on_threshold_points(self) -> None:
        """Boundary points are non-binary and should still be rejected by MASK."""
        self.assertGreaterEqual(self.mask([1.0 / 3.0]), 1.0)
        self.assertGreaterEqual(self.mask([2.0 / 3.0]), 1.0)

    def test_mask_is_positive_just_inside_unsafe_interval(self) -> None:
        """A tiny move inside the interval must trigger the mask."""
        self.assertGreater(self.mask([(1.0 / 3.0) + 1e-6]), 0.0)
        self.assertGreater(self.mask([(2.0 / 3.0) - 1e-6]), 0.0)

    def test_midpoint_coordinate_contributes_full_reject_unit(self) -> None:
        """The midpoint 0.5 must be enough to force a hard reject on its own."""
        self.assertGreaterEqual(self.mask([0.5]), 1.0)


if __name__ == "__main__":
    unittest.main()
