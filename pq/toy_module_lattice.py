"""路线 A A2 使用的非生产 module-lattice reference relation。

该模块只为固定负循环卷积 verifier 提供确定性 oracle 和测试材料。构造
``A(z-c) mod q = t`` 会直接泄露与 secret 相关的线性信息，不具备生产签名安全性，
不得用于真实认证或替代 ML-DSA。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import random
from typing import Sequence

from pq.signature_scheme import KeyPair


Polynomial = tuple[int, ...]
ModuleVector = tuple[Polynomial, ...]
ModuleMatrix = tuple[tuple[Polynomial, ...], ...]


@dataclass(frozen=True)
class ToyModuleLatticeParameters:
    """定义 research-only module-lattice relation 的小型固定参数。"""

    ring_degree: int = 4
    module_rank: int = 2
    modulus: int = 17
    matrix_seed: int = 0
    secret_bound: int = 1

    def __post_init__(self) -> None:
        """拒绝不适合 uint16/int16 编码或固定环电路的参数。"""

        for name, value in (
            ("ring_degree", self.ring_degree),
            ("module_rank", self.module_rank),
            ("modulus", self.modulus),
            ("matrix_seed", self.matrix_seed),
            ("secret_bound", self.secret_bound),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be a built-in integer")
        if self.ring_degree < 2 or self.ring_degree & (self.ring_degree - 1):
            raise ValueError("ring_degree must be a power of two greater than one")
        if self.module_rank <= 0:
            raise ValueError("module_rank must be positive")
        if self.modulus < 3 or self.modulus >= (1 << 15):
            raise ValueError("modulus must be in the range [3, 32767]")
        if self.matrix_seed < 0 or self.matrix_seed >= (1 << 64):
            raise ValueError("matrix_seed must fit an unsigned 64-bit integer")
        if self.secret_bound <= 0 or self.secret_bound + 1 >= self.modulus:
            raise ValueError("secret_bound must leave room for a signed challenge")

    @property
    def module_width(self) -> int:
        """返回展开后的 module coefficient 总数。"""

        return self.ring_degree * self.module_rank

    @property
    def response_bound(self) -> int:
        """返回 ``z=s+c`` 的逐坐标绝对值上界。"""

        return self.secret_bound + 1

    @property
    def response_l1_bound(self) -> int:
        """返回 one-hot challenge 下响应向量的 L1 上界。"""

        return (self.module_width * self.secret_bound) + 1


class ToyModuleLatticeSignatureScheme:
    """提供 research-only module-lattice relation 的 keygen/sign/reference verify。

    该构造不提供不可伪造性。它的唯一用途是让 A2 fixed circuit 能与一个清晰、
    独立且确定性的普通 Python oracle 比较。
    """

    research_only = True
    production_ready = False

    def __init__(
        self,
        seed: int = 0,
        parameters: ToyModuleLatticeParameters | None = None,
    ) -> None:
        """固定公开 module matrix，并初始化确定性测试密钥随机源。"""

        if type(seed) is not int:
            raise TypeError("seed must be a built-in integer")
        self.parameters = parameters or ToyModuleLatticeParameters()
        self._rng = random.Random(seed)
        self._matrix = self._build_matrix()

    @property
    def public_key_bytes(self) -> int:
        """返回 module target 的 uint16 wire 长度。"""

        return self.parameters.module_width * 2

    @property
    def secret_key_bytes(self) -> int:
        """返回 small secret 的 int16 wire 长度。"""

        return self.parameters.module_width * 2

    @property
    def signature_bytes(self) -> int:
        """返回 signed response 的 int16 wire 长度。"""

        return self.parameters.module_width * 2

    def keygen(self) -> KeyPair:
        """生成确定性 small secret 和对应公开 module target。"""

        parameters = self.parameters
        flat_secret = tuple(
            self._rng.randint(-parameters.secret_bound, parameters.secret_bound)
            for _ in range(parameters.module_width)
        )
        secret = self._unflatten(flat_secret)
        target = self._module_multiply(secret)
        return KeyPair(
            public_key=self._encode_canonical(self._flatten(target)),
            secret_key=self._encode_signed(flat_secret),
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """计算 ``z=s+c``；该响应仅用于研究 relation，不是安全签名。"""

        if type(message) is not bytes:
            raise TypeError("message must be built-in bytes")
        secret = self._decode_signed(secret_key)
        if any(abs(value) > self.parameters.secret_bound for value in secret):
            raise ValueError("secret coefficient exceeds the configured bound")
        challenge = self._flatten(self.challenge_vector(message))
        response = tuple(
            secret_value + challenge_value
            for secret_value, challenge_value in zip(
                secret,
                challenge,
                strict=True,
            )
        )
        return self._encode_signed(response)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """使用普通 Python oracle 验证 module-lattice relation 与响应范数。"""

        if type(message) is not bytes:
            return False
        try:
            target = self.decode_public_target(public_key)
            response = self.decode_response(signature)
        except (TypeError, ValueError):
            return False
        return self.verify_relation(target, response, self.challenge_vector(message))

    def verify_relation(
        self,
        public_target: Sequence[Sequence[int]],
        response: Sequence[Sequence[int]],
        challenge: Sequence[Sequence[int]],
    ) -> bool:
        """以普通整数/模运算提供 A2 fixed core 的独立 reference oracle。"""

        try:
            target = self._validate_module_vector(
                public_target,
                name="public_target",
                min_value=0,
                max_value=self.parameters.modulus - 1,
            )
            response_values = self._validate_module_vector(
                response,
                name="response",
                min_value=-32768,
                max_value=32767,
            )
            challenge_values = self._validate_module_vector(
                challenge,
                name="challenge",
                min_value=-1,
                max_value=1,
            )
        except (TypeError, ValueError):
            return False
        flat_response = self._flatten(response_values)
        if any(
            abs(value) > self.parameters.response_bound for value in flat_response
        ):
            return False
        if sum(abs(value) for value in flat_response) > self.parameters.response_l1_bound:
            return False
        flat_challenge = self._flatten(challenge_values)
        if sum(abs(value) for value in flat_challenge) != 1:
            return False
        response_projection = self._module_multiply(response_values)
        challenge_projection = self._module_multiply(challenge_values)
        recovered = tuple(
            tuple(
                (left - right) % self.parameters.modulus
                for left, right in zip(left_poly, right_poly, strict=True)
            )
            for left_poly, right_poly in zip(
                response_projection,
                challenge_projection,
                strict=True,
            )
        )
        return recovered == target

    def public_module_matrix(self) -> ModuleMatrix:
        """返回 verifier 编译所需的不可变公开 module matrix。"""

        return self._matrix

    def challenge_vector(self, message: bytes) -> ModuleVector:
        """把消息确定性映射为 L1 范数为一的 signed module challenge。"""

        if type(message) is not bytes:
            raise TypeError("message must be built-in bytes")
        digest = hashlib.sha256(b"saga-a2-module-challenge-v1" + message).digest()
        index = int.from_bytes(digest[:8], "little") % self.parameters.module_width
        sign = 1 if digest[8] & 1 else -1
        flat = [0 for _ in range(self.parameters.module_width)]
        flat[index] = sign
        return self._unflatten(tuple(flat))

    def decode_public_target(self, encoded: bytes) -> ModuleVector:
        """严格解码 canonical ``Z_q`` 公开 target。"""

        return self._unflatten(self._decode_canonical(encoded))

    def decode_response(self, encoded: bytes) -> ModuleVector:
        """严格解码 int16 signed response，范数检查留给 relation。"""

        return self._unflatten(self._decode_signed(encoded))

    def _build_matrix(self) -> ModuleMatrix:
        """从公开 seed 确定性派生 ``R_q`` 上的方形 module matrix。"""

        parameters = self.parameters
        seed_bytes = parameters.matrix_seed.to_bytes(8, "little", signed=False)
        rows: list[tuple[Polynomial, ...]] = []
        for row_index in range(parameters.module_rank):
            row: list[Polynomial] = []
            for column_index in range(parameters.module_rank):
                coefficients: list[int] = []
                for coefficient_index in range(parameters.ring_degree):
                    digest = hashlib.sha256(
                        b"saga-a2-module-matrix-v1"
                        + seed_bytes
                        + row_index.to_bytes(2, "little")
                        + column_index.to_bytes(2, "little")
                        + coefficient_index.to_bytes(2, "little")
                    ).digest()
                    coefficients.append(
                        int.from_bytes(digest[:2], "little") % parameters.modulus
                    )
                row.append(tuple(coefficients))
            rows.append(tuple(row))
        return tuple(rows)

    def _module_multiply(self, vector: ModuleVector) -> ModuleVector:
        """用 reference Python arithmetic 计算 module matrix-vector product。"""

        modulus = self.parameters.modulus
        result: list[Polynomial] = []
        for row in self._matrix:
            accumulated = [0 for _ in range(self.parameters.ring_degree)]
            for multiplier, polynomial in zip(row, vector, strict=True):
                product = self._negacyclic_multiply(multiplier, polynomial)
                for index, value in enumerate(product):
                    accumulated[index] += value
            result.append(tuple(value % modulus for value in accumulated))
        return tuple(result)

    def _negacyclic_multiply(
        self,
        left: Polynomial,
        right: Polynomial,
    ) -> Polynomial:
        """在 ``Z[x]/(x^n+1)`` 中执行普通 reference 负循环卷积。"""

        width = self.parameters.ring_degree
        output = [0 for _ in range(width)]
        for left_index, left_value in enumerate(left):
            for right_index, right_value in enumerate(right):
                degree = left_index + right_index
                if degree < width:
                    output[degree] += left_value * right_value
                else:
                    output[degree - width] -= left_value * right_value
        return tuple(output)

    def _validate_module_vector(
        self,
        values: Sequence[Sequence[int]],
        *,
        name: str,
        min_value: int,
        max_value: int,
    ) -> ModuleVector:
        """校验 module rank、ring degree、原生整数类型和系数区间。"""

        if len(values) != self.parameters.module_rank:
            raise ValueError(f"{name} has the wrong module rank")
        normalized: list[Polynomial] = []
        for polynomial in values:
            if len(polynomial) != self.parameters.ring_degree:
                raise ValueError(f"{name} has the wrong ring degree")
            checked: list[int] = []
            for value in polynomial:
                if type(value) is not int:
                    raise TypeError(f"{name} coefficients must be built-in integers")
                if value < min_value or value > max_value:
                    raise ValueError(f"{name} coefficient is outside its domain")
                checked.append(value)
            normalized.append(tuple(checked))
        return tuple(normalized)

    def _flatten(self, vector: ModuleVector) -> tuple[int, ...]:
        """按 module row-major 顺序展开多项式向量。"""

        return tuple(value for polynomial in vector for value in polynomial)

    def _unflatten(self, values: Sequence[int]) -> ModuleVector:
        """把固定宽度 coefficient 序列恢复为 module polynomial vector。"""

        if len(values) != self.parameters.module_width:
            raise ValueError("encoded module vector has the wrong coefficient count")
        degree = self.parameters.ring_degree
        return tuple(
            tuple(values[offset : offset + degree])
            for offset in range(0, len(values), degree)
        )

    def _encode_canonical(self, values: Sequence[int]) -> bytes:
        """把 canonical ``Z_q`` 系数编码为 little-endian uint16。"""

        return b"".join(value.to_bytes(2, "little") for value in values)

    def _decode_canonical(self, encoded: bytes) -> tuple[int, ...]:
        """解码固定长度 uint16，并拒绝非 canonical ``Z_q`` 系数。"""

        if type(encoded) is not bytes:
            raise TypeError("encoded public target must be built-in bytes")
        if len(encoded) != self.public_key_bytes:
            raise ValueError("encoded public target has the wrong length")
        values = tuple(
            int.from_bytes(encoded[offset : offset + 2], "little")
            for offset in range(0, len(encoded), 2)
        )
        if any(value >= self.parameters.modulus for value in values):
            raise ValueError("encoded public target is not canonical modulo q")
        return values

    def _encode_signed(self, values: Sequence[int]) -> bytes:
        """把 small signed coefficient 编码为 little-endian int16。"""

        return b"".join(
            value.to_bytes(2, "little", signed=True) for value in values
        )

    def _decode_signed(self, encoded: bytes) -> tuple[int, ...]:
        """解码固定长度 int16 coefficient vector。"""

        if type(encoded) is not bytes:
            raise TypeError("encoded signed vector must be built-in bytes")
        if len(encoded) != self.signature_bytes:
            raise ValueError("encoded signed vector has the wrong length")
        return tuple(
            int.from_bytes(
                encoded[offset : offset + 2],
                "little",
                signed=True,
            )
            for offset in range(0, len(encoded), 2)
        )
