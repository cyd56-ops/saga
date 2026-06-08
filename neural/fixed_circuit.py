"""Utilities for auditing deterministic fixed neural circuits."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TrainableStateFinding:
    """记录固定电路中发现的可训练状态位置。"""

    path: str
    reason: str


_SCALAR_TYPES = (str, bytes, bytearray, int, float, bool, type(None))
_TRAINING_STATE_ATTRIBUTE_NAMES = frozenset(
    {
        "optimizer",
        "optim",
        "scheduler",
    }
)
_TRAINING_METHOD_NAMES = frozenset(
    {
        "backward",
        "configure_optimizers",
        "fit",
        "optimizer_step",
        "train_step",
        "training_step",
        "zero_grad",
    }
)


def find_trainable_state(module: object) -> tuple[TrainableStateFinding, ...]:
    """递归检查固定电路对象中是否存在可训练状态。"""
    findings: list[TrainableStateFinding] = []
    _visit(module, path=module.__class__.__name__, seen=set(), findings=findings)
    return tuple(findings)


def assert_fixed_circuit(module: object) -> None:
    """断言固定神经电路没有可训练参数或梯度入口。"""
    findings = find_trainable_state(module)
    if findings:
        detail = "; ".join(
            f"{finding.path}: {finding.reason}" for finding in findings
        )
        raise AssertionError(f"trainable state found in fixed circuit: {detail}")


def _visit(
    value: Any,
    *,
    path: str,
    seen: set[int],
    findings: list[TrainableStateFinding],
) -> None:
    # 只审计对象图中的固定电路子模块，避免递归进入密钥字节、矩阵系数等不可训练标量数据。
    if isinstance(value, _SCALAR_TYPES):
        return

    object_id = id(value)
    if object_id in seen:
        return
    seen.add(object_id)

    if getattr(value, "requires_grad", False):
        findings.append(
            TrainableStateFinding(path=path, reason="requires_grad is true")
        )

    if getattr(value, "trainable", False):
        findings.append(TrainableStateFinding(path=path, reason="trainable is true"))

    if _is_torch_parameter_like(value):
        findings.append(
            TrainableStateFinding(path=path, reason="parameter requires gradients")
        )

    _inspect_parameter_iterator(value, path=path, findings=findings)
    _inspect_training_entrypoints(value, path=path, findings=findings)

    if isinstance(value, dict):
        for key, item in value.items():
            _visit(item, path=f"{path}[{key!r}]", seen=seen, findings=findings)
        return

    if _is_iterable_container(value):
        for index, item in enumerate(value):
            _visit(item, path=f"{path}[{index}]", seen=seen, findings=findings)
        return

    submodules = getattr(value, "submodules", None)
    if callable(submodules):
        for index, child in enumerate(submodules()):
            _visit(
                child,
                path=f"{path}.submodules()[{index}]",
                seen=seen,
                findings=findings,
            )

    try:
        attributes = vars(value)
    except TypeError:
        return

    for name, item in attributes.items():
        if name.startswith("__"):
            continue
        if name in _TRAINING_METHOD_NAMES and callable(item):
            findings.append(
                TrainableStateFinding(
                    path=f"{path}.{name}",
                    reason="training entrypoint is present",
                )
            )
        if name in _TRAINING_STATE_ATTRIBUTE_NAMES and item is not None:
            findings.append(
                TrainableStateFinding(
                    path=f"{path}.{name}",
                    reason="training state attribute is present",
                )
            )
        _visit(item, path=f"{path}.{name}", seen=seen, findings=findings)


def _inspect_parameter_iterator(
    value: Any,
    *,
    path: str,
    findings: list[TrainableStateFinding],
) -> None:
    """检查 PyTorch 风格 ``parameters()`` 暴露的参数是否仍可训练。"""
    parameters = getattr(value, "parameters", None)
    if not callable(parameters):
        return

    try:
        iterator = parameters()
    except TypeError:
        return

    for index, parameter in enumerate(iterator):
        if bool(getattr(parameter, "requires_grad", False)):
            findings.append(
                TrainableStateFinding(
                    path=f"{path}.parameters()[{index}]",
                    reason="parameter requires gradients",
                )
            )


def _inspect_training_entrypoints(
    value: Any,
    *,
    path: str,
    findings: list[TrainableStateFinding],
) -> None:
    """识别明确会执行训练更新的入口，但不误判 PyTorch ``train()`` 模式切换。"""
    for name in _TRAINING_METHOD_NAMES:
        attribute = vars(type(value)).get(name)
        if callable(attribute):
            findings.append(
                TrainableStateFinding(
                    path=f"{path}.{name}",
                    reason="training entrypoint is present",
                )
            )


def _is_iterable_container(value: Any) -> bool:
    """判断对象是否是需要递归检查的普通容器。"""
    return isinstance(value, (tuple, list, set, frozenset)) or (
        isinstance(value, Iterable) and not hasattr(value, "__dict__")
    )


def _is_torch_parameter_like(value: Any) -> bool:
    """识别 PyTorch 风格的可训练参数而不强依赖 torch。"""
    return (
        value.__class__.__name__ == "Parameter"
        and value.__class__.__module__.startswith("torch")
        and bool(getattr(value, "requires_grad", False))
    )
