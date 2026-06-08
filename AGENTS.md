# AGENTS.md

## Project / 项目

This repository implements a research prototype named **SAGA-PQ-CAN**.

本仓库实现一个名为 **SAGA-PQ-CAN** 的研究原型。

**English**

SAGA-PQ-CAN = SAGA-style agent governance + post-quantum signature verification + Shamir-secured DNN/CNN authentication neuron.

The goal is to build a defensive authentication middleware for agentic systems. It must not implement offensive exploitation functionality. Security tests are allowed only to verify that invalid or real-valued signatures are rejected.

**中文**

SAGA-PQ-CAN = SAGA 风格的智能体治理架构 + 后量子签名验签 + 经过 Shamir 安全变换保护的 DNN/CNN 认证神经元。

目标是构建一个用于智能体系统的防御型认证中间件。不得实现攻击性利用功能。安全测试只允许用于验证非法签名和实数值签名会被拒绝。

---

## Engineering rules / 工程规则

**English**

- Use Python 3.11+.
- Prefer small, reviewable patches.
- Do not rewrite unrelated modules.
- Do not introduce global mutable state for cryptographic keys.
- Do not commit private keys, generated secrets, model checkpoints, or large binary artifacts.
- Put generated test keys under temporary directories created during tests.
- All public APIs must have type hints.
- Use deterministic test seeds where possible.
- Add docstrings for every public class/function.
- When the active conversation context is close to its limit, Codex should proactively warn the user and suggest updating `SAGA_PQ_CAN_WORKLOG.md`, preserving a checkpoint, and restarting the chat window.
- When Codex creates or substantially changes code, every new or substantially changed function should include a concise Chinese comment or docstring explaining what the function implements. Prefer docstrings for public functions and short comments for private/local helpers when a docstring would be noisy.
- When Codex adds or modifies Chinese comments/docstrings, do not use language-label prefixes such as `中文：`; write natural Chinese explanations directly.
- Code comments should be necessary and targeted: emphasize complex logic, edge cases, protocol semantics, and non-obvious implementation details. Do not mechanically add comments to self-evident code.

**中文**

- 使用 Python 3.11+。
- 优先提交小而易审查的 patch。
- 不要重写无关模块。
- 不要为密码密钥引入全局可变状态。
- 不要提交私钥、生成的秘密、模型 checkpoint 或大型二进制文件。
- 测试中生成的测试密钥应放在测试运行时创建的临时目录中。
- 所有公开 API 必须包含类型标注。
- 在可行时使用确定性测试随机种子。
- 每个公开类和公开函数都应添加 docstring。
- 当当前对话上下文接近上限时，Codex 应主动提醒用户，并建议先更新 `SAGA_PQ_CAN_WORKLOG.md`、保留 checkpoint，然后重启对话窗口。
- Codex 新建或实质修改代码时，每个新建或实质修改的函数都应有简明中文注释或 docstring，说明该函数实现什么功能。公开函数优先使用 docstring；私有/局部 helper 如果 docstring 显得冗余，可使用短中文注释。
- Codex 新增或修改中文注释/docstring 时，不要使用 `中文：` 这类语言标签前缀；直接写自然中文说明。
- 代码注释应当必要且有重点：优先说明复杂逻辑、边界条件、协议语义和不直观的实现细节；不要给显而易见的代码机械地铺满注释。

---

## Cryptography rules / 密码学规则

**English**

- Do not hand-roll production cryptography.
- For production-style post-quantum signatures, use an adapter interface around a vetted library when available.
- If an ML-DSA/Dilithium implementation is not available in the environment, implement only a clearly labeled toy LWE/SIS-style verifier for research and testing.
- Never place signing private keys inside the neural verifier.
- The neural authentication module must verify signatures using only public information.
- The DNN/CNN verifier must be treated as a compiled deterministic circuit, not a trained classifier.

**中文**

- 不要手写生产级密码算法。
- 对生产风格的后量子签名，应在可用时通过 adapter 接入经过审查的库。
- 如果环境中没有 ML-DSA/Dilithium 实现，只能实现一个明确标注为 toy 的 LWE/SIS 风格 verifier，用于研究和测试。
- 不得把签名私钥放入神经验签器。
- 神经认证模块只能使用公开信息进行验签。
- DNN/CNN 验签器应被视为编译得到的确定性电路，而不是训练出来的分类器。

---

## Neural crypto rules / 神经密码规则

**English**

- Do not use sigmoid/softmax as the authentication decision.
- The authentication output must be a hard 0/1-style gate after Shamir STEP/RECT/MASK protection.
- Implement STEP_1_3, RECT_1_3, and MASK exactly as fixed ReLU/Linear modules.
- The verifier module must have `requires_grad=False` for all fixed weights unless a test explicitly checks gradients.
- The default failure behavior is reject/drop/audit, never partial authorization.

**中文**

- 不要用 sigmoid/softmax 作为认证决策。
- 认证输出必须是在 Shamir STEP/RECT/MASK 保护之后的硬 0/1 风格 gate。
- 必须将 STEP_1_3、RECT_1_3 和 MASK 精确实现为固定 ReLU/Linear 模块。
- 除非某个测试明确需要检查梯度，否则 verifier 模块中所有固定权重都应设置 `requires_grad=False`。
- 默认失败行为是 reject/drop/audit，绝不能做部分授权。

---

## Git safety / Git 同步安全

**English**

- Codex should prepare a commit-ready checkpoint summary before ending a session.
- Codex may run `git status`.
- To reduce data-loss risk, Codex should preserve a local checkpoint before exit.
- Automatic push, when used for backup, must go only to a dedicated backup branch such as `backup/<current-branch>` and not to the main development branch.
- Before any push, show the exact file list to be committed.
- If the file list includes secrets, generated credentials, local DB files, model outputs, or `paper/`, do not push automatically; keep only the local checkpoint and record the blocker.

**中文**

- Codex 应在会话结束前准备可提交的 checkpoint 摘要。
- Codex 可以运行 `git status`。
- 为降低数据丢失风险，Codex 退出前应保留一次本地 checkpoint。
- 如需自动 push 作为备份，只能推送到专用备份分支，例如 `backup/<current-branch>`，不得自动推送到主开发分支。
- push 前必须展示将提交的文件列表。
- 如果待提交文件包含 secrets、生成的凭据、本地数据库文件、模型输出或 `paper/`，则不得自动 push；此时只保留本地 checkpoint，并记录阻塞原因。
- 当 Codex 需要请求用户同意执行命令或提权操作时，应同时附上简明中文解释，说明要做什么、为什么要做，以及用户是否应当同意。

---

## Testing commands / 测试命令

Run before completion:

在完成任务前运行：

```bash
python -m pytest -q
python -m pytest -q tests/security
python -m pytest -q tests/integration
```

If ruff/mypy are configured, also run:

如果仓库配置了 ruff/mypy，也运行：

```bash
ruff check .
mypy .
```

---

## Definition of done / 完成标准

**English**

A task is done only if:

1. Tests pass.
2. New modules have unit tests.
3. Security invariants are documented.
4. The PR summary explains what was implemented, what was not implemented, and which tests were run.
5. Any toy cryptographic component is clearly labeled as non-production.

**中文**

只有满足以下条件，任务才算完成：

1. 测试通过。
2. 新模块有单元测试。
3. 安全不变量已经写入文档。
4. PR 总结说明实现了什么、没有实现什么、运行了哪些测试。
5. 任何 toy 密码组件都明确标注为非生产用途。
