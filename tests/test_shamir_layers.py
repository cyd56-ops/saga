"""Tests for fixed Shamir STEP/RECT/MASK layers."""

from __future__ import annotations

import unittest

from neural import MASK, RECT13, STEP13


class ShamirLayerTests(unittest.TestCase):
    """Verify deterministic behavior of the fixed Shamir layers."""

    def setUp(self) -> None:
        """Create fresh fixed layers for each test."""
        self.step = STEP13()
        self.rect = RECT13()
        self.mask = MASK()

    def test_step_binary_points(self) -> None:
        """Binary endpoints should map to binary outputs."""
        self.assertEqual(self.step(0.0), 0.0)
        self.assertEqual(self.step(1.0), 1.0)

    def test_step_safe_regions(self) -> None:
        """The safe outer regions should clamp to 0 and 1 as specified."""
        self.assertEqual(self.step(1.0 / 3.0), 0.0)
        self.assertEqual(self.step(2.0 / 3.0), 1.0)
        self.assertAlmostEqual(self.step(0.5), 0.5)

    def test_rect_unsafe_region(self) -> None:
        """Unsafe transition inputs should produce a positive rectangle value."""
        self.assertEqual(self.rect(0.0), 0.0)
        self.assertEqual(self.rect(1.0), 0.0)
        self.assertAlmostEqual(self.rect(0.5), 1.0)

    def test_mask_zero_on_binary_inputs(self) -> None:
        """Pure binary inputs should not trigger the unsafe mask."""
        self.assertEqual(self.mask([0.0, 1.0, 0.0, 1.0]), 0.0)

    def test_mask_positive_on_unsafe_input(self) -> None:
        """Any unsafe coordinate should contribute a full hard-reject unit."""
        self.assertGreaterEqual(self.mask([0.0, 0.5, 1.0]), 1.0)

    def test_mask_boundary_points_are_non_binary_and_rejected(self) -> None:
        """Boundary points may map to hard STEP values but still trigger MASK."""
        self.assertEqual(self.mask([1.0 / 3.0]), 1.0)
        self.assertEqual(self.mask([2.0 / 3.0]), 1.0)

    def test_fixed_submodules_have_no_grad_flag(self) -> None:
        """All fixed submodules should advertise non-trainable state."""
        for module in self.step.submodules():
            self.assertFalse(module.requires_grad)
        for module in self.rect.submodules():
            self.assertFalse(module.requires_grad)
        self.assertFalse(self.mask.sum_layer.requires_grad)
        for module in self.mask.rect.submodules():
            self.assertFalse(module.requires_grad)


if __name__ == "__main__":
    unittest.main()
