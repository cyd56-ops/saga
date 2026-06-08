"""Fixed Shamir-style ReLU/Linear layers for SAGA-PQ-CAN.

These layers are deterministic and non-trainable. They intentionally avoid
framework-specific training machinery so the prototype can run in the current
environment without introducing a heavyweight dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

EPSILON = 1e-12


def _canonicalize_scalar(value: float) -> float:
    """Round away insignificant floating-point noise near zero."""
    if abs(value) <= EPSILON:
        return 0.0
    return value


@dataclass(frozen=True)
class FixedLinear:
    """A fixed affine map with non-trainable weights."""

    weights: tuple[float, ...]
    bias: float = 0.0
    requires_grad: bool = False

    def __call__(self, inputs: float | Sequence[float]) -> float:
        """Apply the affine map to a scalar or fixed-size sequence."""
        if isinstance(inputs, (int, float)):
            values = (float(inputs),)
        else:
            values = tuple(float(value) for value in inputs)

        if len(values) != len(self.weights):
            raise ValueError(
                f"expected {len(self.weights)} inputs, received {len(values)}"
            )

        total = sum(
            weight * value for weight, value in zip(self.weights, values, strict=True)
        ) + self.bias
        return _canonicalize_scalar(total)


@dataclass(frozen=True)
class FixedReLU:
    """A fixed ReLU activation with no trainable state."""

    requires_grad: bool = False

    def __call__(self, value: float) -> float:
        """Return ``max(0, value)``."""
        return max(0.0, _canonicalize_scalar(float(value)))


@dataclass(frozen=True)
class FixedSum:
    """A fixed linear summation over an input sequence."""

    requires_grad: bool = False

    def __call__(self, values: Iterable[float]) -> float:
        """Return the sum of all values."""
        return _canonicalize_scalar(sum(float(value) for value in values))


class STEP13:
    """Implement ``STEP_1_3`` exactly as a fixed ReLU/Linear composition."""

    def __init__(self) -> None:
        """Build the fixed submodules for ``STEP_1_3``."""
        self.shift_one_third = FixedLinear((1.0,), bias=-(1.0 / 3.0))
        self.shift_two_thirds = FixedLinear((1.0,), bias=-(2.0 / 3.0))
        self.relu = FixedReLU()
        self.combine = FixedLinear((3.0, -3.0))

    def __call__(self, value: float) -> float:
        """Evaluate ``STEP_1_3(x)`` for a scalar input."""
        return self.combine(
            (
                self.relu(self.shift_one_third(value)),
                self.relu(self.shift_two_thirds(value)),
            )
        )

    def submodules(self) -> tuple[object, ...]:
        """Return the fixed submodules used by this layer."""
        return (
            self.shift_one_third,
            self.shift_two_thirds,
            self.relu,
            self.combine,
        )


class RECT13:
    """Implement ``RECT_1_3`` exactly as a fixed ReLU/Linear composition."""

    def __init__(self) -> None:
        """Build the fixed submodules for ``RECT_1_3``."""
        self.identity = FixedLinear((1.0,))
        self.shift_one_third = FixedLinear((1.0,), bias=-(1.0 / 3.0))
        self.shift_two_thirds = FixedLinear((1.0,), bias=-(2.0 / 3.0))
        self.shift_one = FixedLinear((1.0,), bias=-1.0)
        self.relu = FixedReLU()
        # Scale the rectangle by 3 so a single unsafe coordinate contributes
        # a full hard-reject unit to MASK.
        self.combine = FixedLinear((3.0, -3.0, -3.0, 3.0))

    def __call__(self, value: float) -> float:
        """Evaluate ``RECT_1_3(x)`` for a scalar input."""
        return self.combine(
            (
                self.relu(self.identity(value)),
                self.relu(self.shift_one_third(value)),
                self.relu(self.shift_two_thirds(value)),
                self.relu(self.shift_one(value)),
            )
        )

    def submodules(self) -> tuple[object, ...]:
        """Return the fixed submodules used by this layer."""
        return (
            self.identity,
            self.shift_one_third,
            self.shift_two_thirds,
            self.shift_one,
            self.relu,
            self.combine,
        )


class MASK:
    """Implement ``MASK(x_1, ..., x_n) = sum_i RECT_1_3(x_i)``.

    Under the current hard-gate semantics, any single non-binary coordinate in
    the unsafe interval contributes at least ``1`` to the mask.
    """

    def __init__(self) -> None:
        """Build the fixed submodules for ``MASK``."""
        self.rect = RECT13()
        self.sum_layer = FixedSum()

    def __call__(self, values: Iterable[float]) -> float:
        """Evaluate ``MASK`` over a finite sequence of scalar inputs."""
        return self.sum_layer(self.rect(value) for value in values)

    def submodules(self) -> tuple[object, ...]:
        """Return the fixed submodules used by this layer."""
        return (self.rect, self.sum_layer)
