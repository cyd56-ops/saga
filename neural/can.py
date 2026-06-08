"""Execution-layer CAN gate for the first SAGA-PQ-CAN prototype."""

from __future__ import annotations

from typing import Sequence

from neural.shamir_layers import MASK, STEP13
from neural.verifier_wrapper import CompoundBitVerifier


class CAN:
    """A hard authentication gate built from fixed STEP/RECT/MASK layers."""

    def __init__(self, verifier: CompoundBitVerifier) -> None:
        """Store the verifier and fixed Shamir layers."""
        self.verifier = verifier
        self.step_in = STEP13()
        self.step_out = STEP13()
        self.mask = MASK()

    def _step_inputs(self, bits: Sequence[int | float]) -> list[float]:
        """Project inputs through ``STEP_1_3`` coordinate-wise."""
        return [self.step_in(bit) for bit in bits]

    def can_accept_compound_bits(self, bits: Sequence[int | float]) -> int:
        """Return a hard ``0`` or ``1`` for a concatenated request bit vector."""
        mask_value = self.mask(bits)
        if mask_value > 0.0:
            return 0

        # 只有所有坐标通过 MASK 的二值检查后，才把比特交给签名 verifier。
        stepped_bits = self._step_inputs(bits)
        try:
            raw_verify_output = self.verifier.verify_compound_bits(stepped_bits)
        except ValueError:
            return 0

        gated_output = max(0.0, self.step_out(float(raw_verify_output)) - mask_value)
        return int(gated_output == 1.0)

    def can_accept(
        self,
        public_key_bits: Sequence[int | float],
        message_bits: Sequence[int | float],
        signature_bits: Sequence[int | float],
    ) -> int:
        """对拆分的公开密钥、消息和签名比特返回硬 ``0/1`` 认证结果。"""
        compound_bits = [
            *public_key_bits,
            *message_bits,
            *signature_bits,
        ]
        return self.can_accept_compound_bits(compound_bits)

    def submodules(self) -> tuple[object, ...]:
        """返回 CAN 依赖的固定验签器与 Shamir 保护层。"""
        return (self.verifier, self.step_in, self.step_out, self.mask)
