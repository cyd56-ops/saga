"""Tests for fixed-circuit audit invariants used by PQ-CAN."""

from __future__ import annotations

import hashlib
import unittest

from neural import (
    CAN,
    MASK,
    RECT13,
    STEP13,
    CompiledToyLWEVerifier,
    assert_fixed_circuit,
    find_trainable_state,
)
from pq import ToyLWESignatureScheme


class FixedCircuitAuditTests(unittest.TestCase):
    """Verify DNN/CAN components are audited as fixed deterministic circuits."""

    def test_shamir_layers_have_no_trainable_state(self) -> None:
        """Shamir STEP/RECT/MASK 固定层整体不能暴露可训练状态。"""
        for layer in (STEP13(), RECT13(), MASK()):
            assert_fixed_circuit(layer)
            self.assertEqual(find_trainable_state(layer), ())

    def test_compiled_verifier_and_can_remain_fixed_after_valid_evaluation(self) -> None:
        """一次验签执行前后都不能产生训练状态或梯度入口。"""
        scheme = ToyLWESignatureScheme(seed=109)
        key_pair = scheme.keygen()
        message = hashlib.sha256(b"fixed-circuit-e10").digest()
        signature = scheme.sign(key_pair.secret_key, message)
        verifier = CompiledToyLWEVerifier(scheme, message_bytes=len(message))
        can = CAN(verifier)

        assert_fixed_circuit(verifier)
        assert_fixed_circuit(can)
        self.assertEqual(can.can_accept(
            _bytes_to_big_endian_bits(key_pair.public_key),
            _bytes_to_big_endian_bits(message),
            _bytes_to_big_endian_bits(signature),
        ), 1)
        assert_fixed_circuit(verifier)
        assert_fixed_circuit(can)

    def test_parameter_iterator_with_trainable_parameter_is_reported(self) -> None:
        """PyTorch 风格 ``parameters()`` 返回可训练参数时必须被审计发现。"""

        class ParameterLike:
            def __init__(self, requires_grad: bool) -> None:
                self.requires_grad = requires_grad

        class ModuleWithParameters:
            def parameters(self):
                """Return parameter-like objects as a torch module would."""
                return iter((ParameterLike(False), ParameterLike(True)))

        findings = find_trainable_state(ModuleWithParameters())

        self.assertEqual(len(findings), 1)
        self.assertIn("parameters()[1]", findings[0].path)
        self.assertEqual(findings[0].reason, "parameter requires gradients")

    def test_training_state_and_update_entrypoints_are_reported(self) -> None:
        """optimizer 或训练更新入口不能出现在固定 verifier 对象图中。"""

        class ModuleWithTrainingState:
            def __init__(self) -> None:
                self.optimizer = object()

            def training_step(self) -> None:
                """A disallowed training update entrypoint."""

        findings = find_trainable_state(ModuleWithTrainingState())
        reasons = {finding.reason for finding in findings}

        self.assertIn("training state attribute is present", reasons)
        self.assertIn("training entrypoint is present", reasons)

    def test_plain_train_mode_method_is_not_treated_as_optimizer_entrypoint(self) -> None:
        """普通 ``train()`` 模式切换不等同于训练更新入口，避免误报。"""

        class ModuleWithTrainMode:
            def train(self, mode: bool = True) -> "ModuleWithTrainMode":
                """Mimic torch.nn.Module.train without optimizer state."""
                return self

        self.assertEqual(find_trainable_state(ModuleWithTrainMode()), ())


def _bytes_to_big_endian_bits(payload: bytes) -> list[int]:
    """将 bytes 展开为测试用大端 bit vector，避免依赖被测对象状态。"""
    bits: list[int] = []
    for byte in payload:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


if __name__ == "__main__":
    unittest.main()
