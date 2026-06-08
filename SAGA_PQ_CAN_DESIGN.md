# SAGA-PQ-CAN Design Document

# SAGA-PQ-CAN 设计文档

## 1. Title / 标题

**SAGA-PQ-CAN: Post-Quantum Neural Authentication Gates for Governed Agentic Systems**

**SAGA-PQ-CAN：面向受治理智能体系统的后量子神经认证门控**

---

## 2. Summary / 摘要

**English**

SAGA-PQ-CAN extends the SAGA agent governance architecture with a post-quantum signature verification gate implemented as a Shamir-secured DNN/CNN authentication neuron.

The design keeps SAGA’s original governance structure: Provider, user registration, agent registration, contact policy, one-time keys, access control tokens, and direct inter-agent TLS communication. The extension does not replace SAGA. Instead, it adds an execution-layer authentication gate inside the receiving agent:

```text
SAGA protocol admission
    -> post-quantum request authentication
    -> Shamir-secured neural authentication gate
    -> execution admission for LLM / memory / tool / delegation
```

The goal is not to replace SAGA, but to add:

1. post-quantum request authentication;
2. execution-layer hard gating inside the receiving agent;
3. protection against real-valued DNN verifier bypass.

**中文**

SAGA-PQ-CAN 在 SAGA 智能体治理架构上增加一个后量子签名验签 gate，并将其实现为经过 Shamir 安全变换保护的 DNN/CNN 认证神经元。

该设计保留 SAGA 原有治理结构：Provider、用户注册、智能体注册、Contact Policy、一次性密钥、访问控制 token，以及智能体之间的直接 TLS 通信。扩展部分不是替代 SAGA，而是在 receiving agent 内部增加一层执行级认证门控：

```text
SAGA 协议层准入
    -> 后量子请求认证
    -> Shamir-secured 神经认证 gate
    -> 面向 LLM / memory / tool / delegation 的执行层准入
```

目标不是替代 SAGA，而是增加：

1. 后量子请求认证；
2. receiving agent 内部的执行层硬门控；
3. 防止 DNN 验签器被实数输入绕过。

---

## 3. Motivation / 动机

**English**

SAGA provides user-controlled governance for AI agents. Users register agents with a Provider, define contact policies, and use OTK-derived access control tokens to control inter-agent communication. The initiating agent later attaches access tokens to direct communication with the receiving agent.

This extension introduces an additional authentication layer at the receiving agent. The layer verifies a post-quantum signature over the SAGA-bound request context and then controls whether the request can reach the LLM prompt, memory system, tool executor, or delegation chain.

The neural verifier must not be a trained classifier. It must be a deterministic compiled verifier protected by Shamir-style STEP/RECT/MASK layers.

**中文**

SAGA 为 AI agents 提供用户可控的治理机制。用户通过 Provider 注册 agents，定义 contact policies，并使用由 OTK 派生的 access control tokens 控制 agent 间通信。后续 initiating agent 在与 receiving agent 的直接通信中携带这些 tokens。

本扩展在 receiving agent 本地增加一层认证机制。该层对绑定 SAGA 上下文的请求签名进行验签，然后决定请求能否进入 LLM prompt、memory、tool executor 或 delegation chain。

神经验签器不能是训练出来的分类器。它必须是确定性编译得到的 verifier，并由 Shamir 风格的 STEP/RECT/MASK 层保护。

---

## 4. Background / 背景

### 4.1 SAGA baseline / SAGA 基线

**English**

SAGA includes:

- User registration.
- Agent registration.
- Provider-maintained user and agent registries.
- Agent contact policies.
- Public one-time keys stored by the Provider.
- Access control tokens encrypted under shared agent-derived keys.
- Direct agent-to-agent communication after token issuance.

The receiving agent enforces access control by checking tokens during communication.

**中文**

SAGA 包含：

- 用户注册；
- agent 注册；
- Provider 维护的 user registry 和 agent registry；
- agent contact policies；
- Provider 存储的公开一次性密钥；
- 使用 agent 派生共享密钥加密的 access control tokens；
- token 签发后的 agent-to-agent 直接通信。

receiving agent 在通信过程中通过检查 token 来执行访问控制。

---

### 4.2 Shamir secure DNN cryptography / Shamir 安全 DNN 密码实现

**English**

A naive ReLU-DNN implementation of a cryptographic function may be correct on binary inputs but insecure on real-valued inputs. For signature verification, the attack objective is not key recovery, but real-valued signature forgery: finding a real-valued signature vector that makes the DNN verifier output accept.

The Shamir secure transformation wraps a DNN verifier D as:

```text
SecureDNN = MaskLayer ∘ STEP_out ∘ D ∘ STEP_in
```

where:

```text
STEP_1_3(x) = 3 * (ReLU(x - 1/3) - ReLU(x - 2/3))

RECT_1_3(x) = 3 * (
    ReLU(x)
    - ReLU(x - 1/3)
    - ReLU(x - 2/3)
    + ReLU(x - 1)
)

MASK(x_1, ..., x_n) = sum_i RECT_1_3(x_i)
```

Final output:

```text
out = ReLU(STEP_1_3(D(STEP_1_3(input))) - MASK(input))
```

Binary inputs are preserved. Unsafe real-valued inputs are rejected.

**中文**

一个朴素的 ReLU-DNN 密码函数实现，可能在二进制输入上是正确的，但在实数输入上不安全。对于签名验签，攻击目标不是恢复密钥，而是实数签名伪造：找到一个实数值签名向量，使 DNN 验签器输出 accept。

Shamir 安全变换将 DNN 验签器 D 包装为：

```text
SecureDNN = MaskLayer ∘ STEP_out ∘ D ∘ STEP_in
```

其中：

```text
STEP_1_3(x) = 3 * (ReLU(x - 1/3) - ReLU(x - 2/3))

RECT_1_3(x) = 3 * (
    ReLU(x)
    - ReLU(x - 1/3)
    - ReLU(x - 2/3)
    + ReLU(x - 1)
)

MASK(x_1, ..., x_n) = sum_i RECT_1_3(x_i)
```

最终输出：

```text
out = ReLU(STEP_1_3(D(STEP_1_3(input))) - MASK(input))
```

二进制输入会被保持。unsafe 的实数输入会被拒绝。

---

### 4.3 Post-quantum signature choice / 后量子签名选择

**English**

The production-facing interface should target an ML-DSA/Dilithium-style signature API. ML-DSA is a standardized module-lattice-based digital signature algorithm. For the first research prototype, the implementation may include a toy LWE/SIS-style verifier for testing only.

**中文**

面向生产的接口应以 ML-DSA/Dilithium 风格签名 API 为目标。ML-DSA 是一种标准化的基于 module lattice 的数字签名算法。对于第一版研究原型，可以包含一个 toy LWE/SIS 风格 verifier，但只能用于测试。

---

## 5. Goals / 目标

### G1. Preserve SAGA semantics / 保留 SAGA 语义

**English**

The system must preserve existing SAGA behavior:

- Provider still enforces contact policy during OTK issuance.
- Access control tokens still limit communication by expiration and request quota.
- Receiving agents still reject missing, expired, mismatched, or over-quota tokens.

SAGA remains responsible for protocol-layer admission:

- agent identity;
- provider registry;
- contact policy;
- OTK issuance;
- access control token semantics;
- direct TLS communication.

**中文**

系统必须保留现有 SAGA 行为：

- Provider 在 OTK 签发期间仍负责执行 contact policy；
- Access control token 仍通过过期时间和请求次数上限限制通信；
- Receiving agent 仍拒绝缺失、过期、不匹配或超出 quota 的 token。

SAGA 继续负责协议层准入：

- agent identity；
- provider registry；
- contact policy；
- OTK 签发；
- access control token 语义；
- 直接 TLS 通信。

### G2. Add post-quantum request authentication / 增加后量子请求认证

**English**

Each request from initiating agent B to receiving agent A must carry a post-quantum signature over a canonical request context.

**中文**

从 initiating agent B 到 receiving agent A 的每个请求，都必须携带一个针对 canonical request context 的后量子签名。

### G3. Add neural hard gate / 增加神经硬门控

**English**

The receiving agent must expose a CAN output:

```text
CAN(pk_B, context, signature) -> accept in {0,1}
```

Only accept=1 allows the request to reach the downstream execution layer.

**中文**

Receiving agent 必须暴露一个 CAN 输出：

```text
CAN(pk_B, context, signature) -> accept in {0,1}
```

只有 accept=1 时，请求才能进入下游执行层。

### G4. Protect against real-valued verifier bypass / 防止实数值 verifier 绕过

**English**

The CAN module must reject unsafe real-valued inputs and must not expose a soft authorization score.

**中文**

CAN 模块必须拒绝 unsafe 的实数输入，并且不得暴露软授权分数。

### G5. Keep private keys outside the verifier / 私钥不得进入 verifier

**English**

The CAN module uses only public keys and signed request data. It must never contain signing private keys.

**中文**

CAN 模块只能使用公钥和已签名请求数据。它绝不能包含签名私钥。

### G6. Gate execution surfaces / 门控执行面

**English**

The CAN module must gate at least these execution surfaces:

- message ingress into the LLM prompt/context;
- memory write/read access when policy requires it;
- tool invocation;
- downstream delegation.

**中文**

CAN 模块至少需要门控以下执行面：

- 消息进入 LLM prompt/context；
- 在策略要求下的 memory 读写；
- tool invocation；
- 下游 delegation。

---

## 6. Non-goals / 非目标

**English**

- Do not replace the entire SAGA protocol.
- Do not implement a trained signature classifier.
- Do not claim production security for toy LWE/SIS code.
- Do not fully post-quantum-secure the SAGA key exchange unless PQ-KEM is separately added.
- Do not bypass ordinary token checks.
- Do not allow partial authorization based on continuous gate values.

**中文**

- 不替代整个 SAGA 协议。
- 不实现训练式签名分类器。
- 不声称 toy LWE/SIS 代码具有生产安全性。
- 除非另行加入 PQ-KEM，否则不声称 SAGA key exchange 已完整后量子安全。
- 不绕过普通 token 检查。
- 不允许基于连续 gate 值的部分授权。

---

## 7. System architecture / 系统架构

```text
Initiating Agent B
    |
    | TLS + SAGA request:
    | <token, message, request_envelope, pq_signature>
    v
Receiving Agent A
    |
    v
SAGA transport / TLS
    |
    v
SAGA protocol admission
    |
    | checks token presence, expiry, quota, agent binding
    v
PQ-CAN request gate
    |
    | verifies post-quantum signature over request_envelope
    | protected by STEP/RECT/MASK
    v
Hard gate
    |
    | accept=1
    v
LLM prompt / memory / tool / delegation

If any check fails:
    reject/drop/audit
```

Final authorization is:

```text
allow = saga_token_valid AND can_accept AND internal_policy_accept
```

中文说明：

```text
Initiating Agent B
    |
    | TLS + SAGA 请求:
    | <token, message, request_envelope, pq_signature>
    v
Receiving Agent A
    |
    v
SAGA transport / TLS
    |
    v
SAGA 协议层准入
    |
    | 检查 token 是否存在、是否过期、quota 是否超限、agent 绑定是否正确
    v
PQ-CAN 请求 gate
    |
    | 验证 request_envelope 上的后量子签名
    | 使用 STEP/RECT/MASK 保护
    v
硬门控
    |
    | accept=1
    v
LLM prompt / memory / tool / delegation

如果任何检查失败：
    reject/drop/audit
```

最终授权为：

```text
allow = saga_token_valid AND can_accept AND internal_policy_accept
```

---

## 8. Request context / 请求上下文

**English**

The signed context must be domain-separated and canonicalized.

Recommended fields:

```json
{
  "domain": "SAGA-PQ-CAN-v1",
  "receiver_aid": "aid_A",
  "sender_aid": "aid_B",
  "token_digest": "...",
  "session_id": "...",
  "turn_id": "...",
  "issued_at": "...",
  "expires_at": "...",
  "action_scope": "llm_prompt|memory_read|memory_write|tool_call|tool_call:<tool_name>|delegation",
  "message_digest": "H(message body)",
  "provider_id": "...",
  "content_type": "text|image|json|tool-call",
  "timestamp": "..."
}
```

The canonical message is:

```text
M = HASH(canonical_encode(context))
```

`pq_signature` is detached from `request_envelope`.
It must not be included in `canonical_encode(request_envelope)`.
The signed message is `HASH(canonical_encode(request_envelope))`.

Implementation requirements:

- Use deterministic key ordering.
- Use explicit domain separation.
- Avoid ambiguous string concatenation.
- Include both agent identities.
- Include token-binding fields.
- Include action-scope fields so execution permissions are explicit.
- Include request body hash, not raw large body.
- Allow qualified scopes such as `tool_call:send_email` when the research prototype needs tool-specific authorization.

**中文**

被签名的 context 必须进行 domain separation，并使用 canonical encoding。

推荐字段：

```json
{
  "domain": "SAGA-PQ-CAN-v1",
  "receiver_aid": "aid_A",
  "sender_aid": "aid_B",
  "token_digest": "...",
  "session_id": "...",
  "turn_id": "...",
  "issued_at": "...",
  "expires_at": "...",
  "action_scope": "llm_prompt|memory_read|memory_write|tool_call|tool_call:<tool_name>|delegation",
  "message_digest": "H(message body)",
  "provider_id": "...",
  "content_type": "text|image|json|tool-call",
  "timestamp": "..."
}
```

canonical message 为：

```text
M = HASH(canonical_encode(context))
```

`pq_signature` 是 detached signature，不属于 `request_envelope` 的 canonical encoding。
不允许把 `pq_signature` 放进 `canonical_encode(request_envelope)`。
被签名的消息是 `HASH(canonical_encode(request_envelope))`。

补充要求：

- 第一版允许使用带限定符的 scope，例如 `tool_call:send_email`，用于研究用的 tool 级授权。

实现要求：

- 使用确定性的 key ordering；
- 使用明确的 domain separation；
- 避免有歧义的字符串拼接；
- 同时包含双方 agent 身份；
- 包含 token-binding 字段；
- 包含 action scope 字段，使执行权限显式化；
- 包含 request body hash，而不是直接签大体积原始 body。

---

## 9. Cryptographic interface / 密码接口

Define:

```python
class SignatureScheme(Protocol):
    def keygen(self) -> KeyPair: ...
    def sign(self, sk: bytes, message: bytes) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool: ...
```

Implementations:

1. `ToyLWESignatureScheme`
   - For tests only.
   - Must be clearly labeled non-production.
   - May use simplified SIS/LWE-style linear relation.
   - Must support deterministic tests.

2. `MLDSAAdapter`
   - Production-facing adapter.
   - Wraps a vetted external implementation if available.
   - Must fail clearly if no implementation is installed.

Do not implement production ML-DSA from scratch.

中文说明：

定义统一签名接口。第一版可以实现 `ToyLWESignatureScheme`，但必须明确标注非生产用途。生产方向应使用 `MLDSAAdapter` 接入外部经过审查的 ML-DSA/Dilithium 库。不要从零手写生产级 ML-DSA。

---

## 10. Neural verifier design / 神经 verifier 设计

### 10.1 Input encoding / 输入编码

Inputs to CAN are bit vectors representing:

```text
pk_B || M || signature
```

For binary tests, values must be exactly 0 or 1.

For real-valued tests, values may be arbitrary floats.

中文说明：

CAN 的输入是 bit vector，表示：

```text
pk_B || M || signature
```

二进制测试中，输入值必须严格为 0 或 1。实数测试中，输入可以是任意浮点值。

---

### 10.2 STEP layer / STEP 层

Implement:

```python
STEP_1_3(x) = 3 * (relu(x - 1/3) - relu(x - 2/3))
```

Behavior:

- x <= 1/3 maps to 0.
- x >= 2/3 maps to 1.
- x in (1/3, 2/3) is unsafe transition region.

Important note:

- `STEP_1_3` alone maps the threshold endpoints to hard values.
- The full hard gate still preserves only binary inputs as passable inputs.
- Non-binary boundary inputs such as `1/3` and `2/3` may still be rejected by `MASK`.

中文说明：

实现：

```python
STEP_1_3(x) = 3 * (relu(x - 1/3) - relu(x - 2/3))
```

行为：

- x <= 1/3 映射为 0；
- x >= 2/3 映射为 1；
- x in (1/3, 2/3) 是 unsafe transition region。

重要说明：

- 单独看 `STEP_1_3` 时，阈值端点会被映射到硬值；
- 但完整硬门真正保持可通过的是二进制输入；
- `1/3` 和 `2/3` 这类非二进制边界值仍可能被 `MASK` 拒绝。

---

### 10.3 RECT/MASK layer / RECT/MASK 层

Implement:

```python
RECT_1_3(x) = 3 * (
    relu(x)
    - relu(x - 1/3)
    - relu(x - 2/3)
    + relu(x - 1)
)
MASK(x) = sum(RECT_1_3(x_i))
```

Security behavior:

- If any coordinate is unsafe, MASK >= 1.
- Final output becomes 0 after `relu(output - MASK)`.
- The current implementation may also fail closed earlier by rejecting any input with `MASK > 0`.

For the current hard-reject interpretation, non-binary boundary points are also allowed to contribute positive mask values.

中文说明：

实现：

```python
RECT_1_3(x) = 3 * (
    relu(x)
    - relu(x - 1/3)
    - relu(x - 2/3)
    + relu(x - 1)
)
MASK(x) = sum(RECT_1_3(x_i))
```

安全行为：

- 如果任意坐标 unsafe，则 MASK >= 1；
- 最终输出经过 `relu(output - MASK)` 后变为 0。
- 当前实现也可以在 `MASK > 0` 时更早 fail closed。

按当前 hard-reject 解释，非二进制边界点也允许对 mask 产生正贡献。

---

### 10.4 Compiled verifier / 编译式 verifier

**English**

The first implementation may wrap a deterministic Boolean verifier:

```python
verify_bits(pk_bits, message_bits, sig_bits) -> bit
```

For toy implementation, it is acceptable to call a deterministic Python verifier and expose a Torch wrapper for testing.

For stricter research mode, implement small Boolean/arithmetic gadgets as fixed ReLU modules.

Current `toy_compiled_research` boundary:

- compiled fixed circuit:
  - public matrix projection over the signature vector;
  - public matrix projection over the derived challenge vector;
- deterministic preprocessing:
  - byte/vector decoding;
  - domain-separated SHA-256 challenge derivation;
- deterministic hard gates:
  - modular subtraction;
  - coordinate equality;
  - all-coordinate acceptance aggregation.

This means the current prototype does not claim that SHA-256 or the
hash-to-challenge function is implemented as a neural circuit. It is explicit
deterministic preprocessing feeding a fixed verifier circuit.

**中文**

第一版实现可以包装一个确定性的布尔 verifier：

```python
verify_bits(pk_bits, message_bits, sig_bits) -> bit
```

对于 toy 实现，可以调用一个确定性的 Python verifier，并提供 Torch wrapper 供测试使用。

更严格的研究版本中，可以把小布尔/算术 gadget 实现为固定 ReLU 模块。

当前 `toy_compiled_research` 的边界如下：

- 已编译为固定电路：
  - 签名向量上的公开矩阵投影；
  - challenge 向量上的公开矩阵投影；
- 确定性预处理：
  - 字节 / 向量解码；
  - 带 domain separation 的 SHA-256 challenge 派生；
- 确定性硬门：
  - 模减；
  - 逐坐标等式判断；
  - 全坐标接受聚合。

因此当前原型不声称 SHA-256 或 hash-to-challenge 已实现为神经电路；
它们是显式确定性预处理，随后进入固定 verifier 电路。

---

### 10.5 CAN output / CAN 输出

The output is:

```python
accept = relu(step_out(raw_verify_output) - mask)
```

It must be interpreted as:

- 1: accept
- 0: reject

No intermediate value should grant partial access.

中文说明：

输出为：

```python
accept = relu(step_out(raw_verify_output) - mask)
```

解释方式：

- 1：accept；
- 0：reject。

任何中间值都不应产生部分授权。

---

## 11. SAGA integration / SAGA 集成

### 11.1 Layered order / 分层顺序

Receiving agent execution path:

1. Parse request.
2. Verify TLS/session metadata if available.
3. Verify SAGA token:
   - present;
   - decryptable or valid handle;
   - not expired;
   - quota not exceeded;
   - bound to initiating agent;
   - bound to receiving agent;
   - policy still valid if online check is enabled.
4. Build canonical request envelope.
5. Retrieve initiating agent post-quantum public key.
6. Run CAN for the requested `action_scope`.
7. If CAN accept=1, permit entry into the requested execution surface.
8. Else reject/drop/audit.

中文说明：

Receiving agent 执行链顺序：

1. 解析请求；
2. 如果可用，验证 TLS/session metadata；
3. 验证 SAGA token：
   - 存在；
   - 可解密或 handle 有效；
   - 未过期；
   - quota 未超限；
   - 绑定到 initiating agent；
   - 绑定到 receiving agent；
   - 如果启用在线检查，则 policy 仍然有效；
4. 构造 canonical request envelope；
5. 获取 initiating agent 的后量子公钥；
6. 针对当前 `action_scope` 运行 CAN；
7. 若 CAN accept=1，则允许进入对应执行面；
8. 否则 reject/drop/audit。

### 11.2 Execution surfaces / 执行面

The first implementation must gate at least:

1. ingress into `local_agent.run()` / LLM prompt context;
2. memory read/write when the execution path uses memory;
3. tool invocation;
4. delegation to another agent.

The system may reuse the same CAN module with different `action_scope` values rather than implementing separate cryptosystems for each surface.

中文说明：

第一版至少需要门控：

1. 进入 `local_agent.run()` / LLM prompt context；
2. 当执行路径使用 memory 时的读写；
3. tool invocation；
4. 向其他 agent 的 delegation。

系统可以通过不同的 `action_scope` 复用同一个 CAN 模块，而不是为每个执行面分别实现不同密码系统。

---

### 11.3 Rejection behavior / 拒绝行为

Return one of:

```json
{
  "status": "rejected",
  "reason": "invalid_token | invalid_signature | unsafe_input | expired | quota_exceeded"
}
```

Do not leak detailed cryptographic internals in production logs.

中文说明：

返回类似结果：

```json
{
  "status": "rejected",
  "reason": "invalid_token | invalid_signature | unsafe_input | expired | quota_exceeded"
}
```

生产日志中不要泄露详细密码学内部信息。

---

## 12. CNN / downstream gate / CNN 与下游 gate

For a CNN or multimodal model:

```text
features = CNN(x)
logits = head(features)
accept = CAN(...)
output = gate(accept, logits)
```

Gate behavior:

```text
if accept == 1:
    return logits
else:
    return reject_class_or_drop
```

The first implementation should use ordinary Python control flow for the gate. A fully differentiable ReLU gate can be added later for research, but it must preserve hard-reject semantics.

中文说明：

对于 CNN 或多模态模型：

```text
features = CNN(x)
logits = head(features)
accept = CAN(...)
output = gate(accept, logits)
```

Gate 行为：

```text
if accept == 1:
    return logits
else:
    return reject_class_or_drop
```

第一版实现建议使用普通 Python 控制流。后续研究可以加入完全可微的 ReLU gate，但必须保持 hard-reject 语义。

---

## 13. Minimal retained SAGA kernel / 最小保留 SAGA 内核

For the current research direction, the repository has two distinct tracks. The
active mainline is Solution Two: keep SAGA Core unchanged and add PQ-CAN as an
agent-side runtime gate after SAGA token validation. Within that mainline, the
implementation boundary is split into two kernels:

- **SAGA protocol kernel**: identity, registration, token, contact-policy, and
  transport semantics. This layer must remain usable without importing PyTorch,
  `neural/`, or concrete PQ-CAN verifier implementations.
- **PQ-CAN extension kernel**: canonical request envelopes, detached
  post-quantum signatures, fixed Shamir-protected neural gates, execution
  intent compilation, and receiving-agent execution-surface authorization.
  This layer binds to the protocol kernel after SAGA token validation and must
  fail closed when required envelope, signature, policy, or gate context is
  missing.

中文说明：当前主线不是把 PQ-CAN 混入所有 SAGA 基础代码，而是保留一个轻量
SAGA 协议内核，再在 token 校验之后接入 PQ-CAN 扩展内核。协议内核负责身份、
注册、token、contact policy 和传输语义；扩展内核负责 canonical envelope、
detached PQ signature、固定神经 gate、intent 编译和接收端执行面授权。

### 13.1 SAGA reproduction track / SAGA 复现轨道

Required if the goal is to reproduce the SAGA paper:

- Provider
- User / Agent Registry
- Contact Policy
- OTK
- Access Control Token
- TLS / mTLS
- `experiments/`
- `proofs/`
- `saga/attack_models/`
- benchmark / overhead harness

### 13.2 PQ-CAN prototype track / PQ-CAN 扩展轨道

Required if the goal is to prototype the extension:

- canonical request envelope
- detached `pq_signature`
- toy LWE / ML-DSA adapter interface
- Shamir STEP / RECT / MASK
- SignedRequestExecutionGate
- ReplayStateStore / shared replay marker backend
- Prompt / Memory / Tool / Forwarding gates

Boundary requirements:

- SAGA Core must run without PyTorch and without PQ-CAN enabled.
- PQ-CAN tests are extension tests, not a prerequisite for SAGA Core correctness.
- `saga/` must not depend on `neural/can.py` to preserve baseline protocol operation.
- `neural/` and `pq/` are extension modules and must not become mandatory for the SAGA paper reproduction path.

Replay protection belongs to the PQ-CAN extension kernel. The current
`FileReplayStateStore` gives one local/shared-filesystem backend with atomic
marker creation. It is enough to make different local workdirs or fresh gate
instances share consumed envelope state, but it is not a complete distributed
systems claim. Multi-host deployments should inject a strongly consistent
`ReplayStateStore` implementation instead of relying on per-agent local state.

方案一“用 LWE-CNN 替换 SAGA VerifyPK primitive”只保留为 Future Work / Alternative Design，不是当前实现主线。

For the current PQ-CAN prototype direction, the codebase does not need every historical SAGA artifact on the extension critical path. It does need a stable SAGA protocol kernel and a focused PQ-CAN extension kernel.

Keep in the SAGA protocol kernel:

- `saga/agent.py`
- `saga/provider/provider.py`
- `saga/user/user.py`
- `saga/common/contact_policy.py`
- `saga/common/crypto.py`
- `saga/ca/CA.py`
- `saga/config.py`
- `saga/local_agent.py`

Keep in the PQ-CAN extension kernel:

- `saga/messages.py`
- `saga/intent.py`
- `saga/execution_gate.py`
- `pq/`
- `neural/`
- `tests/` related to deterministic encoding, PQ signature adapters, fixed
  neural gates, execution-gate decisions, and security/integration coverage

Defer from the PQ-CAN prototype critical path unless later needed:

- `experiments/`
- `proofs/`
- `saga/attack_models/`
- large parts of `agent_backend/` that are only for demonstration tasks
- paper-oriented benchmark harnesses
- legacy docs that describe old flows not used by the new design

These deferred directories are not removed from the repository and are not
declared obsolete. They remain useful as paper-reproduction material,
experiment harnesses, adversary catalogs, and demo backends. They are simply
outside the mandatory runtime authorization boundary for the active PQ-CAN
extension unless a specific experiment or test explicitly opts into them.

中文说明：

对当前研究方向而言，代码库不需要把所有历史 SAGA 材料都放在 PQ-CAN 扩展关键路径上，但必须保留两个清晰边界：一个稳定的 SAGA 协议内核，以及一个聚焦的 PQ-CAN 扩展内核。

SAGA 协议内核必须保留：

- `saga/agent.py`
- `saga/provider/provider.py`
- `saga/user/user.py`
- `saga/common/contact_policy.py`
- `saga/common/crypto.py`
- `saga/ca/CA.py`
- `saga/config.py`
- `saga/local_agent.py`

PQ-CAN 扩展内核必须保留：

- `saga/messages.py`
- `saga/intent.py`
- `saga/execution_gate.py`
- `pq/`
- `neural/`
- 与 deterministic encoding、PQ signature adapter、固定神经 gate、execution gate decision、安全和集成覆盖相关的 `tests/`

对于 PQ-CAN 扩展轨道，当前可延后或移出关键路径：

- `experiments/`
- `proofs/`
- `saga/attack_models/`
- 仅服务演示任务的 `agent_backend/` 大部分内容
- 面向论文的 benchmark harness
- 描述旧流程且不再服务新设计的文档

这些目录不是删除对象，也不是失效材料；它们仍可作为 SAGA 论文复现、实验运行、攻击模型目录和 demo backend 使用。只是除非某个实验或测试显式选择它们，否则它们不属于当前 PQ-CAN runtime authorization 的强制边界。

---

## 14. Security invariants / 安全不变量

### I1. Binary correctness / 二进制正确性

For all valid binary inputs:

```text
CAN(pk, M, sig) = 1 iff Verify(pk, M, sig) = true
```

对所有合法二进制输入：

```text
CAN(pk, M, sig) = 1 当且仅当 Verify(pk, M, sig) = true
```

### I2. Invalid binary rejection / 非法二进制拒绝

For invalid binary signatures:

```text
CAN(pk, M, sig_bad) = 0
```

对于非法二进制签名：

```text
CAN(pk, M, sig_bad) = 0
```

### I3. Unsafe real-valued rejection / Unsafe 实数输入拒绝

If any input coordinate lies in the unsafe interval:

```text
1/3 < x_i < 2/3
```

then:

```text
CAN(x) = 0
```

如果任意输入坐标落入 unsafe 区间：

```text
1/3 < x_i < 2/3
```

则：

```text
CAN(x) = 0
```

### I4. No private key in verifier / verifier 中无私钥

The CAN module must not store or receive signing private keys.

CAN 模块不得存储或接收签名私钥。

### I5. No partial authorization / 无部分授权

Any value other than accept=1 is rejection.

任何不是 accept=1 的值都视为拒绝。

### I6. SAGA policy preservation and internal policy preservation / 保留 SAGA policy 与内部策略

CAN cannot override SAGA token failure.
Internal policy gates cannot be bypassed by CAN.
The final decision is:

```text
allow = saga_token_valid AND can_accept AND internal_policy_accept
```

CAN 不能覆盖 SAGA token 失败；
CAN 也不能绕过内部执行策略。
最终决策是：

```text
allow = saga_token_valid AND can_accept AND internal_policy_accept
```

### I7. Signed envelope binding / 已签名 envelope 绑定

Execution must reject unless all of the following hold:

- `request_envelope` parses and canonicalizes successfully
- `sender_aid`, `receiver_aid`, `action_scope`, `token_digest`, and `message_digest` all match the transport request
- the envelope is inside its validity window
- the detached post-quantum signature verifies under the trusted sender public key

Missing, malformed, or mismatched signed request material must fail closed.

只有在以下条件全部成立时，执行层才允许放行：

- `request_envelope` 能成功解析并 canonicalize
- `sender_aid`、`receiver_aid`、`action_scope`、`token_digest`、`message_digest` 与传输请求完全一致
- envelope 处于有效时间窗内
- 分离的后量子签名能在受信发送方公钥下验证通过

缺失、畸形或不匹配的已签名请求材料必须 fail-closed。

---

## 15. Test plan / 测试计划

### Unit tests / 单元测试

- `test_step_binary_points`
- `test_step_safe_regions`
- `test_rect_unsafe_region`
- `test_mask_zero_on_binary`
- `test_mask_positive_on_unsafe`
- `test_can_accepts_valid_binary_signature`
- `test_can_rejects_invalid_binary_signature`
- `test_can_rejects_random_real_signature`
- `test_can_rejects_unsafe_coordinate`
- `test_private_key_not_in_can_state`

### Integration tests / 集成测试

- valid token + valid signature -> forwarded;
- valid token + invalid signature -> rejected;
- expired token + valid signature -> rejected;
- wrong initiator token + valid signature -> rejected;
- missing token -> rejected;
- replayed token over quota -> rejected.

中文说明：

- 有效 token + 有效签名 -> 转发；
- 有效 token + 无效签名 -> 拒绝；
- 过期 token + 有效签名 -> 拒绝；
- 错误 initiator token + 有效签名 -> 拒绝；
- 缺失 token -> 拒绝；
- replayed token 超过 quota -> 拒绝。

### Empirical robustness tests / 经验鲁棒性测试

- random real-valued signatures;
- boundary inputs around 1/3 and 2/3;
- gradient-based smoke test if Torch autograd is enabled.

These empirical tests are not a proof. The proof obligation follows from the Shamir transformation assumptions and correct implementation.

中文说明：

- 随机实数值签名；
- 1/3 和 2/3 附近的边界输入；
- 如果启用 Torch autograd，做基于梯度的 smoke test。

这些经验测试不是证明。证明义务来自 Shamir 变换假设和正确实现。

---

## 16. Suggested package layout / 推荐包结构

```text
pq/
  __init__.py
  signature_scheme.py
  toy_lwe.py
  mldsa_adapter.py

neural/
  __init__.py
  shamir_layers.py
  verifier_wrapper.py
  can.py
  gates.py

saga/
  __init__.py
  agent.py
  local_agent.py
  messages.py
  common/
    contact_policy.py
    crypto.py
  provider/
    provider.py
  user/
    user.py

tests/
  test_contact_policy.py
  test_encoding.py
  test_toy_lwe.py
  test_shamir_layers.py
  test_can.py
  security/
    test_token_validation.py
    test_real_valued_rejection.py
    test_boundary_values.py
  integration/
    test_baseline_agent_flow.py
    test_saga_pq_can_flow.py

docs/
  SECURITY.md
```

---

## 17. Implementation phases / 实现阶段

### Phase 1: Skeleton and canonical context / 阶段 1：骨架与 canonical context

- Add package structure.
- Add canonical encoding.
- Add request context model.
- Add tests for deterministic encoding.



- 添加包结构；
- 添加 canonical encoding；
- 添加 request context model；
- 添加 deterministic encoding 测试。

### Phase 2: Signature interface / 阶段 2：签名接口

- Add `SignatureScheme`.
- Add toy LWE/SIS-style scheme.
- Add ML-DSA adapter stub.
- Add tests.



- 添加 `SignatureScheme`；
- 添加 toy LWE/SIS 风格 scheme；
- 添加 ML-DSA adapter stub；
- 添加测试。

### Phase 3: Shamir layers / 阶段 3：Shamir 层

- Add STEP_1_3.
- Add RECT_1_3.
- Add MASK.
- Add tests for binary, safe, unsafe, and boundary behavior.



- 添加 STEP_1_3；
- 添加 RECT_1_3；
- 添加 MASK；
- 添加 binary、safe、unsafe、boundary 行为测试。

### Phase 4: CAN / 阶段 4：CAN

- Add CAN class.
- Connect encoding, verifier, and Shamir layers.
- Ensure no trainable parameters by default.
- Add binary and real-valued tests.



- 添加 CAN class；
- 连接 encoding、verifier 和 Shamir 层；
- 确保默认无可训练参数；
- 添加二进制和实数值测试。

### Phase 5: SAGA middleware / 阶段 5：SAGA middleware

- Add token pre-check interface.
- Add `allow = saga_token_valid and can_accept and internal_policy_accept`.
- Add reject/drop/audit behavior.
- Add integration tests.



- 添加 token pre-check 接口；
- 添加 `allow = saga_token_valid and can_accept and internal_policy_accept`；
- 添加 reject/drop/audit 行为；
- 添加集成测试。

### Phase 6: Documentation and benchmarks / 阶段 6：文档与 benchmark

- Add SECURITY.md.
- Add README examples.
- Add small benchmark for verification overhead.
- Add limitation notes.



- 添加 SECURITY.md；
- 添加 README 示例；
- 添加小型 verification overhead benchmark；
- 添加限制说明。

---

## 18. Acceptance criteria / 验收标准

The prototype is acceptable if:

1. All tests pass.
2. Binary valid signatures are accepted.
3. Binary invalid signatures are rejected.
4. Real-valued unsafe inputs are rejected.
5. Random real-valued signatures are rejected in empirical tests.
6. Middleware never forwards a request unless both token and CAN pass.
7. No private signing key appears in CAN state.
8. Toy crypto is labeled non-production.
9. The design document and README are updated.



原型满足以下条件才算可接受：

1. 所有测试通过；
2. 合法二进制签名被接受；
3. 非法二进制签名被拒绝；
4. unsafe 的实数值输入被拒绝；
5. 随机实数值签名在经验测试中被拒绝；
6. middleware 只有在 token 和 CAN 都通过时才转发请求；
7. CAN state 中不出现签名私钥；
8. toy crypto 明确标注为非生产用途；
9. 设计文档和 README 已更新。

---

## 19. Known limitations / 已知限制

**English**

- Toy LWE/SIS verifier is not production cryptography.
- ML-DSA adapter depends on external vetted implementation availability.
- Replacing signatures alone does not fully post-quantum-secure SAGA; key exchange also needs PQ-KEM.
- Python control-flow gate is safer for prototype; differentiable gate is optional research work.
- Formal proof of the full implementation is out of scope for the prototype.

**中文**

- Toy LWE/SIS verifier 不是生产级密码实现。
- ML-DSA adapter 依赖外部经过审查的实现是否可用。
- 仅替换签名不能让 SAGA 完整后量子安全；key exchange 也需要 PQ-KEM。
- Python 控制流 gate 对原型更安全；可微 gate 是可选研究工作。
- 完整实现的形式化证明不在该原型范围内。
