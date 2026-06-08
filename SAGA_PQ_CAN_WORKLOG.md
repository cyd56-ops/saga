# SAGA-PQ-CAN 工作文档与工作日志

本文档是本仓库后续复现与改进工作的主文档，同时承担：

- 分步骤工作计划
- 当前进度面板
- 未完成事项清单
- 目标调整记录
- 会话级工作日志

后续在本目录打开 Codex 并输入“根据工作文档继续工作”时，应默认先阅读：

1. [SAGA_PQ_CAN_WORKLOG.md](/home/kali/saga/SAGA_PQ_CAN_WORKLOG.md:1)
2. [AGENTS.md](/home/kali/saga/AGENTS.md:1)
3. [SAGA_PQ_CAN_DESIGN.md](/home/kali/saga/SAGA_PQ_CAN_DESIGN.md:1)

然后按本文档中的“当前工作焦点”和“下一步”继续工作。

## Source of truth

For current implementation status, use:

- Section 3. 当前状态面板
- Section 7. 当前工作焦点

Historical session logs under Section 8 are archival and may contain superseded statements.
Going forward, keep only the most recent seven work-date logs in the active worklog.

## 当前事实来源

判断当前实现状态时，请优先参考：

- 第 3 节：当前状态面板
- 第 7 节：当前工作焦点

第 8 节历史工作日志仅作为归档，可能包含已被后续工作覆盖的旧状态。
后续活动工作日志只保留最近七个工作日期的记录。

## 1. 使用约定

### 1.1 会话开始时

- 先读取本文件的：
  - “2. 项目目标”
  - “3. 当前状态面板”
  - “5. 分阶段计划”
  - “6. 任务看板”
  - “7. 当前工作焦点”
  - “8. 工作日志”
- 如果代码与旧文档冲突，以代码实际状态为准，并把差异写回本文档。
- 如果用户新提出目标，先更新“2. 项目目标”或“9. 目标调整记录”，再开始实现。

### 1.2 会话结束前

- 必须更新本文档中的：
  - “3. 当前状态面板”
  - “6. 任务看板”
  - “7. 当前工作焦点”
  - “8. 工作日志”
- 如果本次工作改变了顺序、范围、假设或风险，必须更新“9. 目标调整记录”。
- 如果有未跑通的测试、未验证的假设、环境阻塞，必须显式写入“阻塞 / 风险”。
- 必须执行一次 `git` 同步检查：
  - 查看 `git status --short`
  - 确认本次会话应同步的文件范围
  - 准备一次可提交的 checkpoint 摘要
- 默认保留一次本地 checkpoint，降低机器损坏或会话中断导致的进度丢失风险。
- 若待提交文件不包含 secrets、生成的凭据、本地数据库文件、模型输出与 `paper/`，则允许自动推送到备份分支：
  - 先展示将提交的文件列表
  - 默认备份分支为 `backup/<current-branch>`
  - 不自动推送到主开发分支
- 若命中敏感路径或因为网络、认证、分支保护、冲突导致无法推送，必须只保留本地 checkpoint，并把失败原因写入“8. 工作日志”。
- 当需要请求用户同意执行命令、联网、提权或推送时，必须附上简明中文解释，说明要做什么、为什么要做，以及是否值得同意。

### 1.3 状态标记

- `未开始`
- `进行中`
- `已完成`
- `阻塞`
- `跳过`

### 1.4 GitHub 同步约定

- 默认要求：每次会话结束前，准备可提交的 checkpoint 状态说明，并尽量保留一次本地 checkpoint。
- 默认远程：`origin`
- 默认做法：
  - 先更新工作文档
  - 再执行 `git status`
  - 再整理本次 checkpoint 摘要与待提交文件范围
- 再形成一次本地 checkpoint
- 满足安全条件时自动执行备份推送：
  - 提交本次 checkpoint
  - `git push origin HEAD:backup/<current-branch>`
- 不自动推送到主开发分支；如需推主分支，仍需用户明确要求。
- 若当前工作区包含大量历史遗留改动，应先在工作日志中注明：
  - 本次提交是否只包含本会话变更
  - 还是包含仓库当前整体快照
- 若用户未特别指定，可使用 `checkpoint / WIP` 风格的提交说明作为本地与备份分支 checkpoint。
- 若发现可能包含敏感信息、临时目录、大型产物、本地数据库文件、模型输出或 `paper/`，不能自动推送，必须只保留本地 checkpoint 并显式记录阻塞原因。

## 2. 项目目标

### 2.1 总目标

在当前 `SAGA` 仓库基础上，逐步推进到：

```text
SAGA 基线可稳定复现
-> 补齐关键协议正确性与最小测试基线
-> 接入 LWE/PQ 风格签名抽象
-> 接入 Shamir-secured CNN/DNN authentication neuron
-> 保持 SAGA 负责协议层准入
-> 让 PQ-CAN 负责执行层准入
-> 只有同时通过两层的请求才可影响 LLM 状态、memory、tool 和 delegation
```

### 2.2 明确范围

本项目当前目标是研究原型，不是生产系统。必须遵守：

- 不手写生产级密码学实现。
- 若无现成 ML-DSA/Dilithium 可用实现，只做明确标注为 `toy` 的 LWE/SIS 风格 verifier。
- `SAGA` 继续负责协议层访问控制：
  - `Agent identity`
  - `Provider registry`
  - `Contact Policy`
  - `OTK`
  - `Access Control Token`
  - `TLS`
- `PQ-CAN` 负责执行层访问控制：
  - 请求进入 `LLM prompt`
  - 请求进入 `memory`
  - 请求触发 `tool executor`
  - 请求触发 `delegation chain`
- 神经验签器只使用公开信息，不持有签名私钥。
- 神经验签器验证的是绑定 `SAGA` 上下文的确定性认证谓词，不是自然语言安全分类器。
- CAN 必须是确定性编译 verifier，不是训练分类器。
- 验签神经元必须作为固定神经电路运行：
  - 所有固定权重、固定门和编译得到的子模块都应满足 `requires_grad=False`
  - 运行时不得暴露训练入口或依赖梯度更新
  - 电路输入只允许使用公开信息：`public_key_bits || canonical_envelope_digest_bits || signature_bits`
- 安全模式下，Agent runtime 必须把 PQ-CAN 放在强制路径中：
  - `LLM prompt`
  - `tool executor`
  - `memory read / write`
  - `delegation`
  均必须先获得已验签的 `LocalExecutionContext`，不能因缺少 gate 或缺少 context 默认放行。
- `LLM` 可以建议 `requested_scopes` / capability intent，但不能决定授权；最终授权只能由 signed envelope、deterministic runtime gate 和本地 policy 裁定。
- 最终门控必须是硬 `0/1`，并且至少满足：
  - `protocol_allow = saga_token_valid`
  - `execution_allow = can_accept`
  - `internal_policy_allow = internal_policy_accept`
  - `allow = protocol_allow AND execution_allow AND internal_policy_allow`
- CAN 至少需要认证四类约束：
  - 请求来源是否合法
  - 请求上下文是否绑定当前 `SAGA token / agent pair / task / time window`
  - 请求是否被授权进入指定执行面
  - 输入是否为合法二进制签名而非实数绕过输入

### 2.3 当前阶段目标

先把仓库推进到“适合动手改执行层认证”的程度，再开始 PQ-CAN 集成。这个前置程度定义为：

1. 主协议链路可跑通或可被稳定验证：
   - `CA -> Provider -> user register -> agent register -> /access -> connect/listen`
2. 关键接入点明确：
   - receiving agent 的 token 检查路径
   - canonical request context / request envelope 构造位置
   - 消息进入 `local_agent.run()` 前的 gate 位置
   - `memory / tool / delegation` 前的 gate 位置
3. 存在最小回归基线：
   - 至少覆盖 token 成功 / 失败
   - 至少覆盖签名成功 / 失败
   - 为后续 real-valued rejection 测试预留目录和入口

在满足以上前置条件后，当前 PQ-CAN 主线进一步收紧为：

1. 先用 `toy/general-matrix LWE -> compiled DNN verifier` 验证架构可行性：
   - verifier 必须是确定性编译电路，不是训练分类器
   - 先证明“合法二进制输入可通过、非法签名可拒绝、real-valued 输入可拒绝”
2. 再升级到 `CNN + Ring/Module-LWE`：
   - 用更匹配卷积结构的格代数替代当前一般矩阵 toy LWE
   - 同时追求更自然的结构表达、潜在效率收益与论文亮点

### 2.4 论文与架构主线

当前论文/系统主线已收敛为：

```text
Execution-Surface Authorization for Agent Runtimes
    + Policy-aware Agent-LLM interface
```

核心定位：

```text
SAGA = protocol admission
PQ-CAN = execution-surface admission
Agent-LLM interface = semantic layer
```

也就是说，Agent-LLM 可以理解 policy、生成 intent、申请 capability、解释拒绝原因，
但最终 `allow/deny` 必须由 deterministic runtime gate 裁定。

当前建议使用的最终授权公式为：

```text
allow =
    saga_token_valid
    AND request_envelope_valid
    AND pq_signature_valid
    AND can_accept
    AND execution_scope_allowed
    AND internal_policy_accept
```

其中：

- `saga_token_valid`：SAGA token、expiry、quota、agent binding 检查通过。
- `request_envelope_valid`：sender / receiver / session / turn / time window / digest 绑定正确。
- `pq_signature_valid`：对 canonical envelope 的 detached signature 验证通过。
- `can_accept`：Shamir-secured 认证神经元输出硬接受。
- `execution_scope_allowed`：请求 scope 落在允许的 execution surface 内。
- `internal_policy_accept`：Prompt / Memory / Tool / Delegation 本地策略通过。

主论文贡献应围绕：

1. 将 agent runtime 的 `prompt / memory / tool / delegation` 建模为受保护执行面。
2. 设计绑定 SAGA token、agent pair、message digest、action scope 和时间窗的 canonical request envelope。
3. 用 Shamir-secured PQ authentication neuron 防止 neural verifier 的 real-valued bypass。
4. 在 SAGA 真实通信链路上验证 positive task success、negative fail-closed、auditability 与 overhead。

## 3. 当前状态面板

最后更新日期：`2026-06-01`

### 3.1 代码实际状态

- `SAGA` 主体代码存在，CA / Provider / User / Agent / experiments / proofs 目录齐全。
- Provider 端已存在：
  - `/register`
  - `/login`
  - `/register_agent`
  - `/update_policy`
  - `/deactivate_agent`
  - `/refresh_otks`
  - `/access`
- User 端已存在对应的：
  - `update_policy()`
  - `deactivate_agent()`
  - `refresh_otks()`
- `contact_policy.match()` 当前已实现“更高 specificity 覆盖更低 specificity”，注释写明“同 specificity 时首个命中优先”。
- `received token` 路径已存在 `_received_token_is_valid_unlocked()`，说明此前死锁问题已经被部分重构。
- `saga/common/crypto.py` 已修复证书有效期使用本地 naive 时间的问题，统一改为 UTC aware 时间戳。
- OTK 签名语义已收紧为绑定 AID 的 canonical payload：
  - `saga/common/crypto.py` 新增 `otk_signature_payload(...)` / `sign_otk(...)` / `verify_otk_signature(...)`
  - `register_agent()` 与 `refresh_otks()` 现在签名 `aid + OTK`，不再只签 raw OTK bytes
  - Provider `/register_agent` 与 `/refresh_otks` 按同一 helper 验签
  - initiating-side 请求新 OTK 时也按同一 helper 验证，防止跨 AID 重放
- 当前仓库已新增 `pq/` 签名抽象层：
  - `pq/signature_scheme.py`
  - `pq/toy_lwe.py`
  - `pq/mldsa_adapter.py`
- `ToyLWESignatureScheme` 已实现为明确标注 `non-production` 的研究/测试用 toy 方案。
- `MLDSAAdapter` 当前为 fail-closed 外部 backend adapter；若未接入外部审查过的 backend，会明确报错，接入时只委托 `keygen/sign/verify`，不在仓库内实现 ML-DSA。
- 当前仓库已新增 canonical request envelope 模块：
  - `saga/messages.py`
- 当前仓库已新增最小 `neural/` 实现：
  - `neural/shamir_layers.py`
  - `neural/verifier_wrapper.py`
  - `neural/can.py`
- 当前仓库已新增第一版 compiled toy LWE verifier：
  - `neural/compiled_lwe_dnn.py`
  - 当前已将 toy LWE 的公开矩阵投影编译成固定 `Linear` 行投影
  - 当前已将模减、逐系数等式门与最终硬聚合器收紧为显式固定模块
  - 当前 challenge 生成仍保留为确定性显式预处理，不冒充“全神经化哈希”
  - 当前已新增显式编译边界对象 `CompiledVerifierBoundary`
  - `ProjectionTrace` 已记录 `challenge_source="deterministic_sha256_preprocessing:not_neural_hash"`
  - README / SECURITY / 设计文档均已固定：SHA-256 challenge 派生不是神经哈希电路，而是 deterministic preprocessing
- 当前仓库已新增固定电路审计 helper：
  - `neural/fixed_circuit.py`
  - `assert_fixed_circuit(...)`
  - `find_trainable_state(...)`
  - 当前已覆盖 compiled verifier 与 `CAN` 组合的递归不可训练状态检查
- 当前 `neural/verifier_wrapper.py` 仍保留原始 wrapper 路径：
  - 已能验证接口与执行层接线
  - 当前 compiled DNN verifier 与 wrapper verifier 并存，便于逐步替换和回归比较
  - `CNN + Ring/Module-LWE` 仍属于后续升级方向
- 当前仓库已新增 execution gate 接口与 receiving-side 钩子：
  - `saga/execution_gate.py`
  - `saga/agent.py` 已可在 `local_agent.run()` 前调用可插拔 execution gate
- 当前 receiving-side 已有第一版 execution gate 钩子：
  - 已可在消息进入 `local_agent.run()` 前做 execution gate 检查
  - 已将 `llm_prompt` 独立建模为显式 prompt execution surface；通过 envelope/CAN 后仍需授权 `llm_prompt` 才能触发 `local_agent.run()`
  - initiating-side 收到 response 后也会先执行 `request_envelope / pq_signature / CAN` 验签，验签失败不会触发本地 `local_agent.run()`
  - `request_envelope / pq_signature` 已进入实际消息格式
  - `tool` 已有实际包装 gate
  - `memory` 已至少有一个真实写入点走 gate
  - `delegation` 已有第一版真实接口，并默认绑定到外层 `Agent.connect(...)`
- 当前 compiled toy LWE verifier 已接入 execution gate 的真实测试闭环：
  - `tests/test_execution_gate.py` 已改用 compiled verifier 路径
  - `tests/integration/test_baseline_agent_flow.py` 的 receiving-side gate 集成用例已改用 compiled verifier 路径
- 当前 `saga/execution_gate.py` 已新增第一版正式 wiring helper：
  - `build_toy_lwe_execution_gate(...)`
  - 可统一装配 compiled verifier 或 wrapper verifier
  - 后续真实 `smolagents` / 模型栈接入时不必继续在各入口手工组装 `CAN + verifier`
- 当前 `saga/agent.py` 已新增第一版 runtime wiring helper：
  - `enable_toy_lwe_runtime_auth(...)`
  - 可一次性为真实 `Agent` 实例挂上：
    - sending-side toy LWE detached signing
    - receiving-side execution gate
    - strict execution-gate safety mode
  - 当前仍属于 research-only wiring，不代表生产方案
- 当前 `saga/config.py` 已新增可选 research-only 配置块：
  - `ToyRuntimeAuthConfig`
  - `AgentConfig.toy_runtime_auth`
  - `ToyRuntimeAuthConfig.strict_execution_gate` 默认启用；PQ-CAN runtime auth 路径缺失 gate/context 时 fail-closed
  - `ToyRuntimeAuthConfig.mode` 现在显式区分：
    - `toy_compiled_research`
    - `toy_wrapper`
    - `mldsa_external`
  - 旧 `verifier_flavor` 配置仍保持兼容；缺省 `mode` 时由 `verifier_flavor` 规范化推导。
  - `mldsa_external` 当前在 config-driven helper 中 fail-closed，避免缺外部 backend 时静默回退到 toy wiring。
- 当前仓库已新增 policy-aware intent/compiler 最小对象：
  - `saga/intent.py`
  - `AgentIntent`
  - `PolicyDecision`
  - `IntentCompiler`
  - LLM/requested scopes 只作为 proposal；最终 signed `authorized_scopes` 由本地 policy 交集生成
- 当前三个真实任务入口已能按配置自动启用 toy runtime auth：
  - `experiments/schedule_meeting.py`
  - `experiments/expense_report.py`
  - `experiments/create_blogpost.py`
- 当前 checked-in agent API 配置已统一迁移到 Codexi OpenAI-compatible endpoint：
  - `agent_backend/config.py` 中 `DEFAULT_OPENAI_API_BASE = "https://oai.codexi.eu.cc/v1"`
  - 所有 `user_configs/*.yaml` 的 `api_base` 均已设置为该 endpoint
  - `agent_backend/base.py` 会对该 endpoint 读取 `OPENAI_API_KEY`
  - 当前 `OpenAIServerModel` 示例模型已统一改为非 dated alias `gpt-5.2`
- 当前仓库已提供可直接用于 experiments 的 research-only 示例配置：
  - `user_configs/emma_pqcan.yaml`
  - `user_configs/raj_pqcan.yaml`
  - 两者已预置 deterministic toy LWE seed 与 trusted toy public key，可直接从 YAML 启用 PQ-CAN runtime auth
- 当前真实测试执行基线文档已落地到仓库根目录：
  - `test_optimized.md`
  - 当前应以该文档定义的 `Batch 1 / Batch 2` 范围与判定标准为准
- 当前工程规则已在根目录 `AGENTS.md` 与 `saga/AGENTS.md` 明确：Codex 新增或修改中文注释/docstring 时，不使用 `中文：` 这类语言标签前缀，直接写自然中文说明。
- 当前真实测试环境已完成第一轮拉起与修复：
  - 本地 `MongoDB` 可用
  - `CA` / `Provider` 可启动
  - `Emma` / `Raj` baseline 用户与 agent 已完成注册
  - 工具数据已成功 reset/seed
- 当前已确认的真实环境修复项：
  - `.venv` 中补装了 `openai`
  - `.venv` 中补装了 `ddgs`
  - `Provider` TLS 证书已重新对齐到当前 `CA`
  - `CA` 文件服务已改为从独立副本目录提供，避免 `saga/ca/ca.crt` 被客户端下载时自覆盖截断
- 当前已新增两处真实测试支撑性修复：
  - `agent_backend/base.py` 对 `OpenAIServerModel` 显式传入 `client_kwargs={"timeout": 60.0}`
  - `saga/common/overhead.py` / `saga/agent.py` 已避免 `agent:llm_backend_init` 未记录时额外抛 `ValueError`
- 当前已补 experiment 入口级集成测试：
  - `tests/integration/test_experiment_runtime_auth_entrypoints.py`
  - 覆盖 `listen` / `query` 两条路径是否正确消费示例 YAML 并装配 runtime auth
  - 覆盖 receiver-side fail-closed 拒绝语义：
    - 缺失 `request_envelope` / `pq_signature` 时拒绝
    - trusted public key 不匹配时拒绝
- 当前 receiver-side 拒绝已具备本地审计原因：
  - `SignedRequestExecutionGate.evaluate_request(...)` 返回结构化 allow/deny decision
  - `Agent.receive_conversation(...)` 会在 gate reject 时记录稳定的本地 reason
  - 当前 gate reject 还会输出结构化 `AUDIT` 记录，便于后续 experiment 结果归档
  - 且会追加到 `<agent workdir>/audit/execution_gate.jsonl`
- 当前正式 `Batch 1` baseline 三任务已重新计数并通过：
  - 运行目录：`experiments/runs/20260519T094007Z-schedule_meeting-expense_report-create_blogpost/`
  - 命令：`.venv/bin/python experiments/batch_run.py --task all --initiator-config user_configs/emma.yaml --receiver-config user_configs/raj.yaml`
  - `schedule_meeting` query：`success=true`
    - `matched_event_time_from = 2026-05-20T09:00:00`
    - `matched_event_time_to = 2026-05-20T09:30:00`
    - `oracle_reason = meeting_scheduled`
  - `expense_report` query：`success=true`
  - `create_blogpost` query：`success=true`
  - 三项均为 baseline 配置，`runtime_auth_enabled=false`
  - 三项 receiver-side audit reject 均为 `0`
- 当前最新 baseline 三任务端到端统计已于 `2026-05-27` 重新采集并通过：
  - 运行目录：`experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/`
  - 结果文件：`end_to_end_stats_summary.json`
  - `succeeded_count=3`, `failed_count=0`, `task_latency_seconds_total=183.258211`, `task_latency_seconds_mean=61.08607033333333`
  - `model_call_count=15`, `audit_record_count=0`, `audit_logging_overhead_record_count=0`
  - `api_cost_available=false`, `token_usage_available=false`
  - `schedule_meeting`: `success=true`, `runtime_auth_enabled=false`, `task_latency_seconds=44.419665`, `model_call_count=6`, `oracle_reason=meeting_scheduled`
  - `expense_report`: `success=true`, `runtime_auth_enabled=false`, `task_latency_seconds=99.166138`, `model_call_count=7`
  - `create_blogpost`: `success=true`, `runtime_auth_enabled=false`, `task_latency_seconds=39.672408`, `model_call_count=2`
- 当前最新 PQ-CAN 三任务端到端统计已于 `2026-05-27` 重新采集并通过：
  - 运行目录：`experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/`
  - 结果文件：`end_to_end_stats_summary.json`
  - `succeeded_count=3`, `failed_count=0`, `task_latency_seconds_total=224.460688`, `task_latency_seconds_mean=74.82022933333333`
  - `model_call_count=22`, `audit_record_count=0`, `audit_logging_overhead_record_count=0`
  - `api_cost_available=false`, `token_usage_available=false`
  - `schedule_meeting`: `success=true`, `runtime_auth_enabled=true`, `task_latency_seconds=48.207244`, `model_call_count=7`, `oracle_reason=meeting_scheduled`
  - `expense_report`: `success=true`, `runtime_auth_enabled=true`, `task_latency_seconds=132.220902`, `model_call_count=12`
  - `create_blogpost`: `success=true`, `runtime_auth_enabled=true`, `task_latency_seconds=44.032542`, `model_call_count=3`
  - `expense_report` 日志中的 `submit_expense_report` permission gate 是模型/工具层行为差异：业务 oracle 最终成功，且 `peer_audit_reject_count=0`，不归类为 PQ-CAN gate reject。
  - `create_blogpost` 日志中的 code parsing retry 是模型输出格式重试：最终保存文档并返回 `<TASK_FINISHED>`，不归类为 PQ-CAN gate reject。
- 为稳定正式计数，`experiments/schedule_meeting.py` 已将 live prompt 从模糊的 “Tuesday” 改成运行时计算的未来工作日 09:00-17:00 绝对日期窗口；此前失败样本已归档到 ignored archive。
- 当前最新正向 baseline 与 PQ-CAN batch 均未出现 PQ-CAN gate reject 审计：
  - baseline 模式未启用 runtime auth，正向样本中 `peer_audit_reject_count=0`
  - PQ-CAN 模式启用 runtime auth，正向样本中 `peer_audit_reject_count=0`
- 当前 experiment 入口已具备统一结果落盘：
  - `experiments/result_logging.py`
  - `tests/test_result_logging.py`
  - 会将 `mode / agent_aid / peer_aid / success / audit_reject_count / audit_reject_reasons`
    追加到 `experiments/results/<task-name>.jsonl`
- 当前真实 baseline 排障已新增结构化 runtime 诊断：
  - `saga/runtime_diagnostics.py`
  - `saga/agent.py` 现会在 initiating / receiving 两侧的 `local_agent.run()` 后
    记录 `memory step / tool call / final answer / error step / LLM elapsed` 摘要
  - 诊断记录会写入 `<agent workdir>/diagnostics/local_agent_runs.jsonl`
  - `experiments/schedule_meeting.py` 当前会额外输出并落盘：
    - initiator 侧 runtime summary
    - receiver 侧 runtime summary
    - receiver 侧 execution-gate audit summary
    - 带稳定 `oracle_reason` 的会议任务判定结果
- 当前仓库已新增只读 preflight 脚本，用于在真实实验前阻断信任链漂移：
  - `experiments/preflight.py`
  - 默认检查：
    - `.ca_static/` 与 `saga/ca/` 是否分离且公钥材料一致
    - `Provider` 证书是否由当前 CA 签发
    - 目标 user / agent 本地证书是否由当前 CA 签发
    - 本地 Provider 数据库中的 user / agent 注册证书是否与本地文件一致
  - 当前新增 opt-in `--model-probe`：
    - 会对配置中的 `OpenAIServerModel` endpoint 发送一条 tiny chat-completions 请求
    - 用于在真实任务前提前发现 key / quota / endpoint / provider availability 问题
    - 默认不联网、不消耗模型 quota
  - `--repair-plan` 只输出建议，不自动修改任何状态
  - 已于 `2026-05-15` 在当前 `emma / raj` 真实环境上实际运行并通过
- 当前仓库已新增第一版正向任务单入口批跑脚本：
  - `experiments/batch_run.py`
  - 默认连续通过 2 次 opt-in model probe 后，才启动本地 `MongoDB / CA file server / Provider`
  - 自动执行工具数据 seed，并按 `listen -> query` 顺序运行选定真实任务
  - 支持 `--task schedule_meeting|expense_report|create_blogpost|all`
  - 对非模型类 preflight 失败 fail-fast，不把证书/信任链问题当成模型波动重试
  - 会拒绝 receiver 端口预先占用，避免 query 误连旧 listener
  - 日志与 probe/preflight JSON 写入 ignored `experiments/runs/`
  - 当前会在 run 目录生成 `end_to_end_stats_summary.json`，汇总真实任务 task latency、model call count、LLM elapsed、execution-gate audit record count 和 logging stats collection latency
- 当前仓库已新增第一版离线负向注入 runner：
  - `experiments/negative_injection_runner.py`
  - 不启动 MongoDB / Provider / 模型后端，直接构造 deterministic signed envelope 与篡改输入
  - 默认覆盖：
    - `tampered_message`
    - `tampered_action_scope`
    - `tampered_authorized_scope`
    - `expired_envelope`
    - `replayed_envelope`
    - `unauthorized_tool_scope`
    - `unauthorized_memory_write`
    - `unauthorized_delegation`
    - `real_valued_signature_input`
    - `untrusted_sender_aid`
    - `wrong_trusted_sender_key`
    - `agent_runtime_prompt_surface_tool_only`
    - `agent_runtime_replayed_envelope`
    - `agent_runtime_scope_escalation_tool`
  - 输出 `negative_injections.jsonl` 与 `negative_injections_summary.json`
  - 结果默认写入 ignored `experiments/runs/`
- 当前仓库已新增第一版 opt-in 真实服务负向 runner：
  - `experiments/real_negative_runner.py`
  - 默认覆盖：
    - `missing_request_envelope`
    - `tampered_message`
    - `prompt_surface_tool_only`
    - `replayed_envelope`
    - `wrong_trusted_sender_key`
  - `run` 模式会启动或复用本地 `MongoDB / CA file server / Provider`
  - receiver 端使用真实 `Agent.listen()` socket listener，并启用 PQ-CAN runtime auth
  - query 端走真实 Provider access、token、TLS 与 socket 连接，只覆盖 handshake 后的 conversation payload 注入
  - 不调用模型后端；receiver local agent 是记录型 stub，负向通过时不应触发
  - 输出 `real_negative_results.jsonl` 与 `real_negative_summary.json`
  - 结果默认写入 ignored `experiments/runs/`
- 当前仓库已新增第一版离线消融与微开销 runner：
  - `experiments/ablation_overhead_runner.py`
  - 不启动 MongoDB / Provider / 模型后端
  - 比较：
    - `saga_only`
    - `ordinary_pq_middleware`
    - `naive_neural_verifier`
    - `shamir_secured_pq_can`
  - 默认输出：
    - `ablation_results.jsonl`
    - `overhead_results.json`
    - `ablation_overhead_summary.json`
  - 统计本地认证组件微开销：
    - `toy_sign`
    - `ordinary_pq_verify`
    - `compiled_verifier`
    - `shamir_can`
    - `execution_gate_evaluate`
- 当前三个真实任务 query 结果已扩展端到端统计字段：
  - `task_latency_seconds`
  - `model_call_count`
  - `local_model_call_count`
  - `peer_model_call_count`
  - `llm_elapsed_seconds_total`
  - `audit_record_count`
  - `audit_logging_overhead_record_count`
  - `logging_stats_collection_latency_seconds`
  - `api_cost_available` / `api_cost_usd`
  - `token_usage_available` / `total_tokens`
  - model call count 优先来自 runtime diagnostics 中新增的 memory-step 模型调用步数，旧诊断缺字段时回退到已结束的 local-agent run 次数。
  - API cost 与 token usage 只汇总底层模型诊断显式暴露的字段；当前未暴露时标记 unavailable，不猜测价格。
- 当前仓库已新增真实端到端论文表格 helper：
  - `experiments/paper_tables.py`
  - 默认读取 `2026-05-27` baseline 与 PQ-CAN 两个 `end_to_end_stats_summary.json`
  - 输出稳定 run-level / task-level JSON 或 Markdown 表格
  - 表格口径包含 task latency、model call count、LLM elapsed、execution-gate audit/logging 统计、API cost/token usage 可用性标记
  - 不把模型/工具 permission text 或 parsing retry 当成 PQ-CAN gate reject；只有 execution-gate audit record 进入 audit 计数
- 当前仓库已新增离线端到端产物验收 helper：
  - `experiments/end_to_end_validation.py`
  - 不启动 MongoDB / CA / Provider，不调用模型后端
  - 可校验 baseline / PQ-CAN 正向 `end_to_end_stats_summary.json`
  - 可校验真实服务负向 runner 的 `real_negative_summary.json` 与 `real_negative_results.jsonl`
  - 当前验收口径要求：
    - 正向任务全部 success
    - baseline 正向任务 `runtime_auth_enabled=false`
    - PQ-CAN 正向任务 `runtime_auth_enabled=true`
    - 正向 execution-gate reject count 为 0
    - 真实负向样本 expected/observed reason 一致
    - 真实负向样本 `side_effect_triggered=false` 且 `local_agent_run_count=0`
- 当前仓库已将原备用执行面方案合入主线：
  - `SAGA Core` 负责协议层准入，不替代 `Provider / Registry / Contact Policy / OTK / Access Control Token / TLS`
  - `PQ-CAN` 负责 execution-surface admission，作为 receiving agent 内部的 deterministic runtime gate
  - `Agent-LLM interface` 只作为 policy-aware semantic layer，可表达 intent / requested scopes，但不能自证授权
  - 最终授权公式已收紧为：
    `allow = saga_token_valid AND request_envelope_valid AND pq_signature_valid AND can_accept AND execution_scope_allowed AND internal_policy_accept`
- 当前 execution-surface authorization 已完成的能力：
  - `request_envelope` 已实现 sender / receiver / token digest / message digest / session / turn / time window / scope 绑定
  - `pq_signature` 已按 detached signature 处理，不进入 canonical envelope
  - toy LWE 路径已经接通到 receiving-side execution gate
  - Shamir `STEP / RECT / MASK` 已有固定实现，并覆盖 binary invalid / real-valued / boundary 拒绝测试
  - compiled verifier / CAN 已有递归固定电路审计，能检查关键子模块没有 `requires_grad=True` 或 PyTorch 风格可训练参数
  - execution gate 已能返回稳定 audit reason，并写入本地审计记录
  - `prompt` 已作为独立 execution surface 检查；仅有 `tool_call:*` scope 的请求不能进入 LLM prompt，且会以 `prompt_scope_not_authorized` 审计拒绝
  - 安全模式下缺失 `execution_gate` 会以 `missing_execution_gate` 拒绝，缺失 `LocalExecutionContext` 会以 `missing_local_execution_context` 拒绝
  - initiating-side inbound response 已纳入同一 gate 路径，覆盖 valid response、missing envelope/signature、tampered message 和 wrong trusted key 的拒绝测试
  - execution gate 已有 seen-request replay 防护；执行路径通过 `consume_request(...)` 消费 envelope digest，重复 envelope 会以 `replayed_request_envelope` 拒绝
  - runtime auth helper 默认将 replay marker 持久化到 agent workdir 下的 `audit/replay/`，新 gate 实例会恢复已消费 envelope digest
  - runtime auth config 已支持显式 `replay_state_dir`，不同本地 workdir / gate 实例可共享同一个文件型 replay marker 后端
  - `ReplayStateStore` 协议已抽出，后续 Redis / DB / strongly consistent backend 可按同一原子 `reserve_request` 语义接入
  - 已有最小 `AgentIntent / PolicyDecision / IntentCompiler`，`Agent._conversation_authorized_scopes(...)` 通过本地 policy 编译 requested scopes，不能把 memory/delegation 或未暴露工具扩进 signed envelope
  - policy-aware intent/compiler 已能区分稳定本地拒绝原因：
    - 入口动作本身不被 policy 允许时为 `policy_reject`
    - requested scopes 额外越权时为 `scope_escalation`
  - 本地执行面权限失败已能和 PQ-CAN 签名 gate 拒绝分开统计：
    - 包装工具入口统一暴露 `tool_not_authorized`
    - 底层执行面保留 `unauthorized_tool_scope` / `unauthorized_memory_read` / `unauthorized_memory_write` / `unauthorized_delegation`
  - `tool / memory / delegation` 已有第一版 `LocalExecutionContext` 局部授权控制
  - `CodeAgent` 已禁用 `smolagents` 自动 base tools 注入；运行时业务工具只来自显式配置并经过本地 execution gate wrapper，内置代码执行器作为 prompt execution 机制处理，不作为额外授权 grant
  - F3/F7 授权公式已完成第一版结构化收口：
    - `ExecutionGateDecision` 显式记录 `saga_token_valid / request_envelope_valid / pq_signature_valid / can_accept / execution_scope_allowed / internal_policy_accept`
    - execution-gate audit JSONL 中新增 `authorization_formula`
    - `Agent.receive_conversation(...)` 与 `Agent.initiate_conversation(...)` 在 token 通过后把 `saga_token_valid=True` 合入 gate decision
    - prompt surface 检查继承 envelope / signature / CAN / token 公式项，并在 `llm_prompt` 未授权时将 `execution_scope_allowed=False`、`internal_policy_accept=False`
    - 本地 policy 不再自动允许任意入口 action；`policy_reject` 会在信封构造前 fail-closed
    - `tool_call:*` 入口不会隐式携带 `llm_prompt`，因此工具入口信封不能进入 prompt surface
  - E10 固定电路冻结约束已完成第一版：
    - `neural/fixed_circuit.py` 现在能识别 PyTorch 风格 `parameters()` 返回的可训练参数
    - 能识别 `optimizer` / `optim` / `scheduler` 这类训练状态属性
    - 能识别 `backward` / `fit` / `training_step` / `train_step` / `optimizer_step` / `zero_grad` / `configure_optimizers` 等训练更新入口
    - 保留对普通 `train()` 模式切换的非误报，避免把只读 PyTorch module API 等同于训练更新
    - `tests/test_fixed_circuit.py` 覆盖 Shamir 层、compiled verifier、CAN 组合、训练参数、训练状态和训练入口
  - 离线负向注入 runner 已覆盖 tampered message/scope、expired/replayed envelope、unauthorized tool/memory/delegation、real-valued signature input、untrusted/wrong sender key
  - 离线负向注入 runner 已新增真实 `Agent.receive_conversation(...)` 路径样本，覆盖 prompt surface tool-only 拒绝、runtime replay 拒绝、runtime tool scope escalation 拒绝且无副作用
  - 离线消融 runner 已能展示 SAGA-only / ordinary PQ / naive neural / Shamir-secured PQ-CAN 在 envelope、scope、real-valued 输入上的覆盖差异
  - 离线开销 runner 已记录 toy signing、ordinary verify、compiled verifier、Shamir CAN、execution gate evaluate 的微基准
  - `MLDSAAdapter` 已有 fail-closed 外部 backend adapter 骨架
- 当前 execution-surface authorization 后续需要补强的能力：
  - replay 防护已支持本地工作目录持久化和共享文件目录后端；完整多主机 / 分布式一致性仍需外部 strongly consistent `ReplayStateStore`
  - 论文级实验矩阵还可继续补强真实任务端到端消融、真实 API 成本与模型调用开销统计
- 按当前设计，代码范围应区分两条轨道：
  - SAGA 协议内核：`saga/agent.py`、`saga/provider/provider.py`、`saga/user/user.py`、`saga/common/*`、`saga/ca/CA.py`、`saga/config.py`、`saga/local_agent.py`
  - PQ-CAN 扩展内核：`saga/messages.py`、`saga/intent.py`、`saga/execution_gate.py`、`pq/`、`neural/`、相关 `tests/`
  - 对 PQ-CAN runtime authorization 强制边界可延后：`experiments/`、`proofs/`、`saga/attack_models/`、大部分 `agent_backend/`
  - 对 SAGA paper reproduction 轨道：`experiments/`、`proofs/`、`saga/attack_models/` 仍属于复现材料
- 当前仓库已新增最小测试基线：
  - `tests/`
  - `tests/security/`
  - `tests/integration/`
  - `tests/test_contact_policy.py`
  - `tests/security/test_token_validation.py`
  - `tests/integration/test_baseline_agent_flow.py`
  - `tests/test_toy_lwe.py`
  - `tests/test_encoding.py`
  - `tests/test_shamir_layers.py`
  - `tests/test_can.py`
  - `tests/test_compiled_lwe_dnn.py`
  - `tests/security/test_real_valued_rejection.py`
  - `tests/security/test_boundary_values.py`
  - `tests/integration/test_baseline_agent_flow.py` 中的 execution gate 入口覆盖
  - `tests/test_negative_injection_runner.py`
- 当前仓库已新增 `SECURITY.md`：
  - 记录 SAGA 与 PQ-CAN 的安全边界
  - 记录 toy LWE / ML-DSA adapter 的非生产与生产接入边界
  - 记录 execution-surface authorization 的负向覆盖矩阵
- 原备用路线草稿 `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md` 已合并进本文档并删除；后续不再作为独立事实来源。
- 当前 `.gitignore` 已额外忽略：
  - `saga/user/*/audit/`
  - 避免 receiving-side execution gate 审计运行产物进入提交范围
- 工作区已做过一次整顿：
  - 已清除大部分仅由换行符漂移造成的已跟踪噪音改动
  - 当前应重点关注的已跟踪源码改动收敛为：
    - `.gitignore`
    - `saga/agent.py`
    - `saga/provider/provider.py`
    - `saga/user/user.py`
    - `saga/common/contact_policy.py`
    - 对应 attack model 文件

### 3.2 已确认的差异

- 现有 [REPRO_GAP_CHECKLIST.md](/home/kali/saga/REPRO_GAP_CHECKLIST.md:1) 与代码已有偏差。
- 其中“缺少 policy update / deactivate / OTK refresh”这一判断已经过时，因为代码里已存在对应接口和客户端逻辑。
- 后续工作应以代码实况和本文档为准，`REPRO_*` 文档可作为历史分析材料，不再作为唯一状态来源。

### 3.3 已完成程度评估

- SAGA 主线代码骨架：`已完成`
- SAGA Phase 0 基线运行验证：`已完成`
- 生命周期接口补齐：`部分完成`
- 核心协议正确性审计：`进行中`
- 最小自动化测试基线：`已完成`
- 论文级实验复现 harness：`进行中`
- 代码范围收缩与关键路径隔离：`进行中`
- PQ/LWE 签名抽象：`进行中`
- canonical request context / request envelope：`进行中`
- Shamir STEP/RECT/MASK：`已完成`
- compiled DNN verifier：`进行中`
- CNN + Ring/Module-LWE verifier：`未开始`
- SAGA + PQ-CAN 执行层集成：`进行中`

### 3.4 阻塞 / 风险

- 已在本环境实际跑通：
  - Python 依赖导入
  - repo-local MongoDB 启动
  - CA 文件服务启动
  - Provider 启动
  - user register / login / register_agent
  - agent-to-agent 基线通信
  - `.venv/bin/python -m pytest -q`
  - `.venv/bin/python -m pytest -q tests/security`
  - `.venv/bin/python -m pytest -q tests/integration`
- 已于 `2026-05-27` 重新确认测试结果：
  - `.venv/bin/python -m pytest -q` -> `192 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-05-30` 重新确认最新 I5 后测试结果：
  - `.venv/bin/python -m pytest -q` -> `196 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-05-30` 重新确认 paper table helper 后测试结果：
  - `.venv/bin/python -m pytest -q` -> `201 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-05-30` 重新确认 real negative runner 后测试结果：
  - `.venv/bin/python -m pytest -q` -> `207 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-05-31` 重新确认 E10 固定电路审计后测试结果：
  - `.venv/bin/python -m pytest -q` -> `222 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-06-01` 重新确认 E7 challenge 边界收口后测试结果：
  - `.venv/bin/python -m pytest -q tests/test_compiled_lwe_dnn.py tests/test_fixed_circuit.py` -> `18 passed`
  - `.venv/bin/python -m pytest -q` -> `223 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-06-01` 重新确认 F6 端到端产物验收 helper 后测试结果：
  - `.venv/bin/python -m pytest -q tests/test_end_to_end_validation.py` -> `7 passed`
  - `.venv/bin/python -m pytest -q tests/test_end_to_end_validation.py tests/test_batch_run.py tests/test_real_negative_runner.py tests/test_paper_tables.py tests/test_negative_injection_runner.py` -> `36 passed`
  - `.venv/bin/python experiments/end_to_end_validation.py --baseline-summary experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json --pq-can-summary experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json --positive-task-count 3 --real-negative-run-dir experiments/runs/20260531T122842Z-real-negative-missing_request_envelope-tampered_message-prompt_surface_tool_only-replayed_envelope-wrong_trusted_sender_key --required-real-negative-scenario missing_request_envelope --required-real-negative-scenario tampered_message --required-real-negative-scenario prompt_surface_tool_only --required-real-negative-scenario replayed_envelope --required-real-negative-scenario wrong_trusted_sender_key` -> `passed=true`
  - `.venv/bin/python -m pytest -q` -> `230 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 已于 `2026-06-01` 重新确认 C2 token 并发消费修复后局部测试结果：
  - `.venv/bin/python -m pytest -q tests/security/test_token_validation.py` -> `12 passed`
  - `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py tests/security/test_token_validation.py` -> `37 passed`
  - `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_execution_gate_factory.py tests/test_agent_runtime_auth.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `43 passed, 12 subtests passed`
  - `.venv/bin/python -m pytest -q` -> `233 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `20 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `29 passed, 12 subtests passed`
  - 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。
- 当前 Shamir 层边界语义已明确：
  - `STEP_1_3` 在 `1/3` 与 `2/3` 上映射到硬值
  - 但完整 hard gate 只承诺保留二进制输入
  - `1/3` 与 `2/3` 这类非二进制边界点可被 `MASK` 拒绝
- 当前 shell 中不存在 `python` 命令；验收命令需使用 repo-local `.venv/bin/python`。
- 当前系统 `python3` 环境默认未安装 `pytest`，本次验收使用 repo-local `.venv`。
- OTK 签名语义已升级为绑定 `aid + OTK` 的 canonical payload，相关生成/验签路径已统一；后续若继续改动，应保持 helper 一致，避免回退到 raw OTK only。
- `pq/toy_lwe.py` 仅用于研究 wiring 与测试，不能作为生产签名方案；生产方向只能通过 `MLDSAAdapter` 接入外部审查过的实现。
- 当前 compiled toy LWE verifier 只完成了第一阶段：
  - 已编译公开矩阵投影
  - 已把模运算、逐系数比较和最终聚合收紧为显式固定模块
  - challenge 生成明确保留为 SHA-256 domain-separated deterministic preprocessing
  - 当前不声称 SHA-256 或 hash-to-challenge 已实现为神经电路
  - 后续若继续推进 compiled DNN 深化，应优先评估是否将模减 / 等式 / 聚合进一步改写为更细粒度固定 ReLU gadget，或进入 E8 的 CNN + Ring/Module-LWE 路线
- 当前新的关键设计风险不在“是否替换 SAGA”，而在“如何把执行层 gate 插到正确节点并保持 deterministic semantics”。
- 当前工作区已清理为干净状态；当前本地 checkpoint 已备份到 `origin/backup/repro-local`，但相对 `origin/repro-local` 仍超前多个提交；后续同步时仍需显式记录：
  - 本次同步范围
  - 是否只包含本会话变更
  - 哪些本地 checkpoint 尚未合并回常规开发分支
- 已补充 `.gitignore` 忽略：
  - `.codex`
  - `.mongodb/`
  - `.mongodata/`
- `git restore` 类操作在本环境下需要写 `.git/index.lock`，因此可能需要仓库内 `git` 写权限。
- API key / 模型后端当前最新状态：
  - 当前 Codex 会话已本地核验 `OPENAI_API_KEY` 存在，但不在仓库日志中记录完整密钥、masked 值或哈希指纹。
  - 旧 key / 新 key 的具体指纹仅用于本地排障，不进入 Git 历史。
  - `gpt-4.1` / `gpt-4.1-mini` alias 曾在 Codexi endpoint 上 timeout，dated snapshot 名称也不再使用。
  - 当前已切换到非 dated alias `gpt-5.2`。
  - `2026-05-16` opt-in `--model-probe` 曾确认 `gpt-5.2@https://oai.codexi.eu.cc/v1` 可返回 chat-completions response。
  - `2026-05-18` 真实 rerun 前 20 秒 `--model-probe` 一度通过，但随后真实 query 与再次 probe 都出现连接 / timeout。
  - 当前最新模型后端阻塞：
    - true query 中 initiating-side `CodeAgent` 生成失败：`AgentGenerationError: Connection error`
    - 随后 `--model-probe --model-probe-timeout 20` 失败：`openai.APITimeoutError: Request timed out.`

## 4. 工作原则

### 4.1 先基线，后改造

在没有最小可回归基线前，不直接大规模替换验签模块。

### 4.2 先抽象，后接入

在没有统一签名接口、canonical context、测试目录前，不直接把 LWE/CNN 代码硬塞进 `saga/agent.py`。

### 4.3 先 DNN，后 CNN

当前 toy LWE 是一般矩阵结构，优先对应固定 `Linear/DNN` 编译实现；`CNN` 只在后续引入 `Ring/Module-LWE` 这类卷积型格结构后再作为主升级方向。

### 4.4 先 middleware，后扩散

PQ-CAN 的主接入点应优先放在 receiving agent 的执行链入口，而不是先重写所有现有 `Ed25519/X509/OTK` 逻辑。

### 4.5 先硬认证，后语义防护

PQ-CAN 当前优先做的是来源、上下文、执行面、二进制输入合法性的硬认证，不把它设计成通用 prompt injection 语义检测器。

## 5. 分阶段计划

## Phase 0：建立可信基线

目标：

- 盘点代码当前实际状态
- 跑通最小主链路
- 明确哪些 `REPRO_*` 判断已过时

完成标准：

- 能用文档描述当前仓库“已经有什么、没什么、跑通了什么、没验证什么”
- 至少形成一份最小环境与运行步骤记录

状态：`已完成`

## Phase 1：补最小测试基线

目标：

- 创建 `tests/`
- 先补最小单元测试与集成测试骨架
- 让后续改造有回归保护

建议先补：

- `tests/test_contact_policy.py`
- `tests/test_token_validation.py`
- `tests/integration/test_baseline_agent_flow.py`

完成标准：

- `python -m pytest -q` 能执行
- 至少能区分“代码失败”和“测试目录不存在”

状态：`已完成`

## Phase 2：补 SAGA 主线正确性

目标：

- 验证并修正 contact policy、token、OTK、通信路径中的关键语义问题
- 识别哪些现有 SAGA 代码是 PQ-CAN 必须依赖的最小协议内核

优先项：

1. contact policy specificity 语义确认与测试
2. token reuse / invalidation / quota 路径测试
3. OTK 签名是否绑定 `aid`
4. `lookup()` 残留路径是否需要清理
5. 将 `experiments / proofs / attack_models / demo agent backend` 从主实现关键路径中分离

完成标准：

- 主链路在“允许 / 拒绝”两侧都有自动化覆盖

状态：`进行中`

## Phase 3：签名接口与 canonical context

目标：

- 加入统一签名抽象
- 为 PQ-CAN 准备 deterministic input encoding
- 固定执行层认证使用的 canonical request envelope

建议产物：

- `pq/signature_scheme.py`
- `pq/toy_lwe.py`
- `pq/mldsa_adapter.py`
- `saga/messages.py` 或等价 canonical context 模块
- `tests/test_encoding.py`
- `tests/test_toy_lwe.py`

建议先固定的 envelope 字段：

- `domain`
- `sender_aid`
- `receiver_aid`
- `token_digest`
- `session_id`
- `turn_id`
- `issued_at`
- `expires_at`
- `action_scope`
- `message_digest`
- `provider_id`
- `content_type`

`pq_signature` 必须作为 detached signature 随请求发送，但不进入 `request_envelope`
的 canonical encoding，避免递归签名并保持签名边界清晰。

完成标准：

- 合法 / 非法 toy 签名可稳定区分
- 同一消息不能脱离原 `token / agent pair / task / time window / action scope` 被复用
- 所有 public API 具备类型标注与 docstring

状态：`进行中`

## Phase 4：Shamir 层与 Compiled DNN CAN

目标：

- 实现 `STEP_1_3`
- 实现 `RECT_1_3`
- 实现 `MASK`
- 先用固定权重构造 deterministic CAN
- 再将 toy/general-matrix LWE 验签逐步替换为 compiled DNN verifier
- 将验签神经元明确收紧为不可训练的固定神经电路：
  - 所有固定 ReLU / Linear / SUM / STEP / RECT / MASK 子模块标记为 `requires_grad=False`
  - 编译自签名 verifier 的矩阵投影、模减、等式门和聚合门也标记为不可训练
  - 若后续引入 PyTorch DNN/CNN/CAN 版本，初始化后必须冻结所有 `Parameter`，并以测试证明没有梯度更新路径
- 固定电路只验证公开材料绑定的认证谓词，不包含 signing secret，也不接受 LLM 输出作为可信授权证明

建议产物：

- `neural/shamir_layers.py`
- `neural/verifier_wrapper.py`
- `neural/can.py`
- `neural/compiled_lwe_dnn.py` 或等价模块
- `tests/test_shamir_layers.py`
- `tests/test_can.py`
- `tests/security/test_real_valued_rejection.py`
- `tests/security/test_boundary_values.py`
- `tests/test_compiled_lwe_dnn.py`

完成标准：

- 二进制合法签名接受
- 二进制非法签名拒绝
- 上下文绑定错误时拒绝
- 未授权执行面请求拒绝
- unsafe 实数输入拒绝
- CAN state 中无签名私钥
- verifier 本体不再只是回调 `scheme.verify()`，而是至少对 toy LWE 的核心验签关系形成固定 DNN 电路实现
- 新增/补强测试能递归检查 verifier / CAN 中所有固定子模块均不可训练
- LLM 建议的 scope 只能作为 envelope / policy 输入，不能绕过固定 verifier 与 runtime gate

状态：`进行中`

## Phase 5：SAGA 执行层集成

目标：

- 在 receiving agent 的执行链加入分层 execution-surface gate：
  - 协议层继续使用既有 `SAGA token` 检查
  - 消息进入 `local_agent.run()` / prompt surface 前做 `request_envelope_valid + pq_signature_valid + can_accept`
  - 进入 `memory` 前做执行授权检查
  - 进入 `tool executor` 前做执行授权检查
  - 进入 `delegation chain` 前做执行授权检查
- 将 runtime 改成安全模式下的强制路径：
  - `execution_gate is None` 不再隐式放行，除非显式进入 legacy / compatibility 模式
  - `LocalExecutionContext is None` 时，`LLM / tool / memory / delegation` 默认拒绝
  - initiating side 和 receiving side 的 inbound turn 都必须通过验签 gate
  - 所有 smolagents base tools 或自动注入工具都必须被包装，或在安全模式下禁用
- 引入 policy-aware Agent-LLM semantic layer：
  - LLM 可输出结构化 intent / requested scopes / justification
  - runtime 将 intent 编译为 canonical request envelope
  - intent 不直接授权，最终仍由 deterministic gate 和本地策略裁定

建议接入位置：

- 优先评估 [saga/agent.py](/home/kali/saga/saga/agent.py:918) 附近的 receiving-side 初始请求处理路径
- 进一步梳理 `LocalAgent` 包装层与工具调用层的可插拔 gate 接口
- 后续可新增 `AgentIntent / PolicyDecision / ScopeRequest / IntentCompiler` 或等价对象，但必须保持授权边界在 runtime gate

完成标准：

- 请求只有在完整授权公式成立时才可影响：
  - `LLM state`
  - `memory`
  - `tool`
  - `delegation`
- scope 不匹配时无法调用对应 tool。
- 未授权 memory write 无法落盘。
- 未授权 delegation 无法发起下游 agent call。
- gate reject 后不会触发 LLM、memory、tool 或 delegation 副作用。
- LLM 提出的 scope escalation 只会产生 `policy_reject` / `scope_not_authorized` 等审计结果，不会扩大 envelope 中已签名的授权范围。

状态：`进行中`

## Phase 6：实验、文档与验收

目标：

- 补 `SECURITY.md`
- 补 benchmark / overhead 记录
- 补 integration / security 测试
- 更新 README 与限制说明
- 补论文级实验矩阵：
  - `SAGA only`
  - `SAGA + ordinary PQ signature middleware`
  - `SAGA + naive neural verifier without Shamir MASK`
  - `SAGA + Shamir-secured PQ-CAN`
- 负向场景至少覆盖：
  - `missing_envelope`
  - `missing_signature`
  - `tampered_message`
  - `tampered_action_scope`
  - `expired_envelope`
  - `replay_envelope`
  - `unauthorized_tool_scope`
  - `unauthorized_memory_write`
  - `unauthorized_delegation`
  - `real_valued_signature_input`
  - `untrusted_sender_key`

完成标准：

- 满足 [AGENTS.md](/home/kali/saga/AGENTS.md:1) 的完成标准
- 每类失败都有稳定 audit reason。
- 每类失败都证明无下游副作用。
- runtime auth enabled 的真实任务成功率和开销有统计。

状态：`进行中`

## 6. 任务看板

### A. 基线与环境

- A1. 记录本地最小运行步骤：`已完成`
- A2. 验证依赖安装与入口命令：`已完成`
- A3. 验证 CA / Provider 是否能在当前环境启动：`已完成`
- A4. 跑通一次最小 user register / agent register：`已完成`
- A5. 跑通一次最小 connect / listen：`已完成`

### B. 测试基线

- B1. 创建 `tests/` 顶层目录：`已完成`
- B2. 创建 `tests/security/`：`已完成`
- B3. 创建 `tests/integration/`：`已完成`
- B4. 补 contact policy 单元测试：`已完成`
- B5. 补 token 校验单元测试：`已完成`
- B6. 补最小基线集成测试：`已完成`

### C. SAGA 正确性

- C1. 确认 `contact_policy.match()` 与论文语义的一致性：`已完成`
- C2. 确认 token reuse / invalidation 路径是否仍有并发风险：`已完成`（第一阶段：active/received token 校验与 quota 扣减改为锁内原子消费）
- C3. 确认 `lookup()` 是否仅为残留 shim：`已完成`
- C4. 评估 OTK 签名绑定 `aid` 的改造成本：`已完成`
- C5. 确认最小 SAGA 内核保留范围：`已完成`（已拆分为 SAGA 协议内核与 PQ-CAN 扩展内核）
- C6. 将非主线目录从当前设计关键路径中降级：`已完成`（`experiments/`、`proofs/`、`saga/attack_models/`、大部分 `agent_backend/` 已记录为非 runtime authorization 强制边界）

### D. PQ 签名抽象

- D1. 设计 `SignatureScheme` 协议接口：`已完成`
- D2. 实现 `ToyLWESignatureScheme`：`已完成`
- D3. 实现 fail-closed `MLDSAAdapter` 外部 backend 适配器：`已完成`
- D4. 为签名接口补测试：`已完成`
- D5. 实现 `saga/messages.py` canonical request envelope：`已完成`
- D6. 为 deterministic encoding 补测试：`已完成`

### E. Neural CAN

- E1. 设计 bit-level input encoding：`已完成`
- E2. 实现 `STEP_1_3`：`已完成`
- E3. 实现 `RECT_1_3`：`已完成`
- E4. 实现 `MASK`：`已完成`
- E5. 实现来源 / 上下文 / action scope 绑定的 `CAN`：`已完成`
- E6. 补 binary / real-valued / boundary 测试：`已完成`
- E7. 将 toy/general-matrix LWE 验签编译成固定 DNN verifier：`已完成`（第一阶段：固定矩阵投影 + 显式 deterministic challenge 预处理边界）
- E8. 评估 `CNN + Ring/Module-LWE` 升级路线：`未开始`
- E9. 递归检查 compiled verifier / CAN 所有固定子模块 `requires_grad=False`：`已完成`
- E10. 明确 PyTorch DNN/CNN/CAN 版本的冻结参数和无训练入口约束：`已完成`

### F. 执行层集成

- F1. 明确消息进入 `local_agent.run()` 前的 gate 接口：`已完成`
- F2. 明确 canonical request context / envelope 构造点：`已完成`
- F3. 接入 `allow = protocol_allow AND execution_allow AND internal_policy_allow`：`已完成`
- F4. 明确 `memory / tool / delegation` 前的 gate 接口：`已完成`
- F5. 定义 reject / drop / audit 返回行为：`已完成`
- F6. 补 end-to-end 集成测试：`已完成`（第一阶段：离线 artifact validator 固化正向/真实负向验收口径）
- F7. 将最终授权公式扩展为 `saga_token_valid AND request_envelope_valid AND pq_signature_valid AND can_accept AND execution_scope_allowed AND internal_policy_accept`：`已完成`
- F8. 将 `prompt` 独立建模为显式 execution surface：`已完成`
- F9. 补 seen-request / replay 状态管理：`已完成`
- F10. 将 `toy mode / compiled research mode / ML-DSA mode` 运行路径进一步拆清：`已完成`
- F11. 安全模式下缺失 `execution_gate` 或 `LocalExecutionContext` 时默认拒绝：`已完成`
- F12. 对 initiating side inbound response 也执行 request envelope / PQ signature / CAN 验签：`已完成`
- F13. 禁用或统一包装 `CodeAgent(add_base_tools=True)` 自动注入工具，避免绕过 tool gate：`已完成`
- F14. 将 LLM requested scope 作为 proposal 处理，并证明不能扩大已签名授权范围：`已完成`

### G. 文档与验收

- G1. 维护本工作文档：`进行中`（本轮已记录中文注释/docstring 语言标签前缀规则）
- G2. 补 `SECURITY.md`：`已完成`
- G3. 更新 README：`已完成`
- G4. 运行规定测试命令并记录结果：`已完成`
- G5. 每次会话结束前准备 checkpoint、审查待提交文件并推送备份分支：`进行中`
- G6. 将真实实验 preflight 规则脚本化并写入文档：`已完成`
- G7. 将模型后端可用性探针接入真实实验 preflight：`已完成`
- G8. 将正向真实任务单入口批跑脚本化并写入文档：`已完成`
- G9. 将备用执行面授权草案合并进主工作文档：`已完成`
- G10. 固化真实端到端 summary 的论文表格口径：`已完成`

### H. 真实测试栈

- H1. 将 `test_optimized.md` 落地为当前真实测试执行基线：`已完成`
- H2. 拉起本地 `MongoDB / CA / Provider` 并完成 baseline 注册：`已完成`
- H3. 完成 `Batch 1` 前置环境修复（证书链、依赖、超时）：`已完成`
- H4. 跑通 `schedule_meeting` baseline 第一条正向任务：`已完成`
- H5. 正式 `Batch 1` baseline 三任务重新计数：`已完成`
- H6. 启动 `PQ-CAN` 正向三任务真实验证：`已完成`
- H7. 启动两个最小负向场景真实验证：`已完成`
- H8. 新增正向任务单入口批跑脚本：`已完成`
- H9. 补负向注入批跑脚本或统一 runner：`已完成`
- H10. 补 prompt surface / replay / execution-scope escalation 的真实负向样本：`已完成`
- H11. 补 `SAGA only / ordinary PQ middleware / naive neural / Shamir-secured PQ-CAN` 消融对比：`已完成`（离线消融第一版已落地，后续可增加真实服务样本）
- H12. 补 gate latency / signature verification latency / Shamir overhead / API cost 统计：`已完成`（离线微开销与真实任务端到端统计第一版已落地；API cost 依赖后端 usage/cost 字段）
- H13. 将离线 runtime-path 负向样本升级为 opt-in 真实服务样本：`已完成`（当前 runner 代码已覆盖 8 个场景；其中 5 个已有历史真实执行 artifact，新增 tool/memory/delegation scope-probe 场景待 opt-in 重跑刷新 artifact）

### I. Policy-Aware Agent-LLM Interface

- I1. 定义 `AgentIntent` 或等价结构化 intent 对象：`已完成`
- I2. 定义 `PolicyDecision / ScopeRequest` 或等价策略裁定对象：`已完成`
- I3. 实现 `IntentCompiler`，将 intent 编译为 canonical request envelope 输入：`已完成`
- I4. 确保 LLM intent 只作为 envelope 构造输入，不作为可信授权证明：`已完成`
- I5. 为 `scope_escalation / tool_not_authorized / policy_reject` 等拒绝原因补稳定审计语义：`已完成`

## 7. 当前工作焦点

当前建议优先顺序：

1. `baseline` 与 `PQ-CAN` 正向三任务已于 `2026-05-27` 重新采集端到端统计并全部通过：
   - baseline 运行目录：`experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/`
   - baseline summary：`succeeded_count=3`, `failed_count=0`, `task_latency_seconds_total=183.258211`, `model_call_count=15`, `audit_record_count=0`
   - PQ-CAN 运行目录：`experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/`
   - PQ-CAN summary：`succeeded_count=3`, `failed_count=0`, `task_latency_seconds_total=224.460688`, `model_call_count=22`, `audit_record_count=0`
   - PQ-CAN 三项均为 `runtime_auth_enabled=true`，`peer_audit_reject_count=0`。
   - `expense_report` 中出现的 `submit_expense_report` permission gate 属于模型/工具层真实行为差异，业务 oracle 最终成功，不是 PQ-CAN gate reject。
   - `create_blogpost` 中出现的 code parsing retry 属于模型输出格式重试，最终保存文档并返回 `<TASK_FINISHED>`，不是 PQ-CAN gate reject。
2. 继续保留并使用结构化 runtime 诊断：
   - receiver workdir 已出现 `diagnostics/local_agent_runs.jsonl`
   - 本轮新增的 `filter_diagnostics_since(...)` 已用来隔离当前运行窗口与历史诊断。
   - 诊断已足以区分后续 model / tool / oracle 问题。
3. `H7` 两个最小负向场景已于 `2026-05-20` 完成：
   - 缺失签名材料：receiver audit reason=`missing_request_envelope`
   - trusted public key 不匹配：receiver audit reason=`signature_verification_failed`
4. 保持 compiled DNN verifier 与 execution gate 主线继续可回归：
   - 当前相关自动化测试已稳定
   - `neural/fixed_circuit.py` 已补递归固定电路审计
   - `tests/test_compiled_lwe_dnn.py` 已证明 compiled verifier / CAN 组合没有可训练状态
5. 原 `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md` 中的路线已经合入本文档，原文件已删除：
   - 已完成部分：request envelope、detached signature、toy LWE gate、Shamir STEP/RECT/MASK、execution gate audit、tool/memory/delegation 第一版 gate、fail-closed ML-DSA adapter、PQ-CAN 正向三任务真实通过、两个最小负向场景真实通过
   - 未来继续部分：mode split、真实服务负向样本、论文级消融与 overhead 统计
6. 当前新增的架构收紧点：
   - 验签神经元要作为 `requires_grad=False` 固定电路，而不是可训练模型
   - 编译来源是 deterministic signature verifier；DNN/CNN/CAN 只是固定电路表达
   - Agent runtime 中 `LLM / tool / memory / delegation` 都必须经过强制 gate
   - LLM 只能建议 scope / intent，不能决定授权或扩大已签名授权
7. `prompt` execution surface 已完成第一版接入：
   - receiving-side `Agent.receive_conversation(...)` 会在 `local_agent.run()` 前要求 `LocalExecutionContext` 授权 `llm_prompt`
   - 仅有 `tool_call:*` scope 的 signed envelope 会被拒绝并记录 `prompt_scope_not_authorized`
   - 当前 legacy 无 execution gate 路径仍保留兼容放行；PQ-CAN strict 模式下缺 gate/context 已改为 fail-closed
8. strict execution-gate safety mode 已完成第一版接入：
   - `enable_toy_lwe_runtime_auth(...)` 默认设置 `agent.strict_execution_gate=True`
   - `ToyRuntimeAuthConfig.strict_execution_gate` 默认 `True`，可显式设为 `False` 做兼容模式测试
   - strict 模式下缺失 `execution_gate` -> `missing_execution_gate`
   - strict 模式下缺失 `LocalExecutionContext` -> `missing_local_execution_context`
9. initiating-side inbound response 验签已完成第一版接入：
   - `Agent.initiate_conversation(...)` 收到 peer response 后先执行 execution gate
   - response 必须绑定 `sender_aid=r_aid`、`receiver_aid=self.aid`、同一 token、message digest 和 `llm_prompt` scope
   - gate reject 会记录结构化 `AUDIT` 并阻止 initiating-side `local_agent.run()`
   - 已覆盖 valid signed response、missing envelope/signature、tampered response message、wrong trusted key
10. seen-request replay 防护已完成第一版接入：
   - `SignedRequestExecutionGate.consume_request(...)` 负责执行路径上的 validate-and-consume
   - `evaluate_request(...)` 保持纯检查，不改变 replay 状态，方便测试和诊断读取
   - `Agent.receive_conversation(...)` / `Agent.initiate_conversation(...)` 实际执行前均使用 consume 路径
   - 重复 envelope digest 会以 `replayed_request_envelope` 拒绝，且不会触发本地 agent
   - 标准 toy runtime helper 会把 replay marker 写入 agent workdir 下的 `audit/replay/`，跨 gate 实例恢复后仍拒绝同一 envelope
   - replay 状态写入失败时以 `replay_state_persistence_failed` fail-closed，不静默放行
   - `FileReplayStateStore` 与 `ReplayStateStore` 已完成第一版；显式配置同一 `replay_state_dir` 时，不同本地 workdir / gate 实例会共享 replay 状态
11. policy-aware intent/compiler 最小对象已完成第一版接入：
   - `saga/intent.py` 定义 `AgentIntent`、`PolicyDecision`、`IntentCompiler`
   - `Agent._conversation_authorized_scopes(...)` 会把 requested scopes 作为 proposal 编译为本地 policy 允许的 signed scopes
   - 未暴露工具、`memory_write`、`delegation` 等未授权 requested scopes 不会进入 signed envelope
12. 离线负向注入 runner 已完成第一版：
   - `experiments/negative_injection_runner.py`
   - 覆盖 tampered message/scope、expired/replayed envelope、unauthorized tool/memory/delegation、real-valued signature input、untrusted/wrong sender key
   - 已扩展真实 `Agent.receive_conversation(...)` runtime-path 场景：
     - `agent_runtime_prompt_surface_tool_only`
     - `agent_runtime_replayed_envelope`
     - `agent_runtime_scope_escalation_tool`
   - 默认输出 JSONL 与 summary 到 ignored `experiments/runs/`
   - `.venv/bin/python experiments/negative_injection_runner.py --output-dir /tmp/saga-negative-runner-runtime-smoke` 已确认 `14/14` PASS
13. 离线消融、微开销和真实端到端统计已完成第一版：
   - `experiments/ablation_overhead_runner.py`
   - 比较 `saga_only / ordinary_pq_middleware / naive_neural_verifier / shamir_secured_pq_can`
   - 当前 smoke 输出显示：
     - `saga_only`: `passed=1/6`, `negative_rejected=0`
     - `ordinary_pq_middleware`: `passed=3/6`, `negative_rejected=2`
     - `naive_neural_verifier`: `passed=3/6`, `negative_rejected=2`
     - `shamir_secured_pq_can`: `passed=6/6`, `negative_rejected=5`
   - 微开销指标包括 `toy_sign / ordinary_pq_verify / compiled_verifier / shamir_can / execution_gate_evaluate`
   - 三个真实任务 query 结果现在包含 task latency、model call count、LLM elapsed、audit/logging 统计字段
   - `experiments/batch_run.py` 会在 run 目录写入 `end_to_end_stats_summary.json`
   - API cost / token usage 只在底层模型诊断显式暴露时汇总；当前未暴露时标记 unavailable，不做价格估算
14. F13 已完成第一版：
   - `agent_backend/base.py` 创建 `CodeAgent` 时设置 `add_base_tools=False`
   - `tests/test_agent_wrapper_gate.py` 覆盖该构造参数，防止 `web_search/user_input` 等 `smolagents` base tools 自动进入未包装工具面
   - 业务工具仍来自 `LocalAgentConfig.tools`，并在 `_wrap_tool_with_execution_gate(...)` 中检查 `tool_call:<tool_name>`
   - 内置代码执行器继续作为 CodeAgent prompt execution 机制存在，不作为额外 tool grant 进入 signed scopes
15. I5 已完成第一版：
   - `IntentCompiler` 现在区分 `policy_reject` 与 `scope_escalation`
   - `Agent._conversation_policy_decision(...)` 可返回带 reason 的本地 policy 裁定，`_conversation_authorized_scopes(...)` 保持原签名 scope 返回行为
   - `LocalExecutionContext.require_*` 会抛出带 `reason/action_scope` 的 `ExecutionAuthorizationError`
   - 包装工具入口将本地工具权限失败统一成 `tool_not_authorized`，避免将模型/工具层 permission failure 误归为 PQ-CAN 签名 gate reject
16. `2026-05-27` baseline/PQ-CAN 真实端到端论文表格口径已固化第一版：
   - `experiments/paper_tables.py` 默认读取两个已归档 summary
   - 支持 `--format json` 和 `--format markdown`
   - run-level 行覆盖成功数、延迟、模型调用、LLM elapsed、audit/logging 统计、cost/token 可用性
   - task-level 行覆盖三任务逐项 latency、model call、local/peer model call、LLM elapsed、audit reject 与 oracle reason
17. opt-in 真实服务负向 runner 已扩展并真实验证：
   - `experiments/real_negative_runner.py`
   - 当前场景：`missing_request_envelope`、`tampered_message`、`prompt_surface_tool_only`、`replayed_envelope`、`wrong_trusted_sender_key`、`unauthorized_tool_scope`、`unauthorized_memory_write`、`unauthorized_delegation`
   - 真实路径覆盖本地 CA/Provider、access/token、TLS socket 和 receiving-side `Agent.listen()`
   - query 侧只覆盖 handshake 后 conversation payload，因此不依赖模型后端
   - receiver local agent 使用记录型 stub；信封/签名/prompt/replay 类拒绝的判断标准是 expected audit reason 且 local run count 为 0
   - tool/memory/delegation scope-probe 类拒绝的判断标准是 prompt 合法进入一次，`LocalExecutionContext` 给出 expected reason，且受保护动作 side-effect 计数为 0
   - `2026-05-31` opt-in 真实运行目录：
     `experiments/runs/20260531T122842Z-real-negative-missing_request_envelope-tampered_message-prompt_surface_tool_only-replayed_envelope-wrong_trusted_sender_key/`
   - `.venv/bin/python experiments/real_negative_runner.py run --scenario all` -> `5/5` PASS
   - 五项均记录 expected audit reason，且 `local_runs=0`；新增三项 scope-probe 场景尚需 opt-in 真实重跑刷新 artifact
18. runtime-auth mode split 已完成第一版：
   - `ToyRuntimeAuthConfig.mode` 支持 `toy_compiled_research` / `toy_wrapper` / `mldsa_external`
   - 旧配置继续通过 `verifier_flavor` 推导 mode，当前 checked-in `*_pqcan.yaml` 解析为 `toy_compiled_research`
   - `enable_toy_lwe_runtime_auth_from_config(...)` 只允许 toy modes 进入 toy LWE wiring
   - `mldsa_external` 缺少显式 vetted backend wiring 时抛出 `RuntimeError`，不降级到 toy signing
   - `README.md` / `SECURITY.md` 已记录三种 mode 的边界
19. F3/F7 授权公式收口已完成第一版：
   - `ExecutionGateDecision.formula_terms()` 暴露六项公式值
   - 审计记录新增 `authorization_formula`
   - signature/CAN 拒绝、prompt surface 拒绝和 token 已通过状态均可在同一 audit record 中区分
   - `Agent._conversation_authorized_scopes(...)` 对 `policy_reject` fail-closed，不再继续构造会被 `RequestEnvelope` 自动加入入口 action 的签名信封
   - `tool_call:*` 入口默认授权集合不包含 `llm_prompt`
20. E7 challenge 派生边界已收口为第一阶段完成：
   - `CompiledVerifierBoundary` 明确区分：
     - fixed circuit：公开矩阵投影
     - deterministic preprocessing：字节 / 向量解码与 SHA-256 challenge 派生
     - deterministic hard gates：模减、逐坐标等式判断、全坐标接受聚合
   - `ProjectionTrace.challenge_source` 稳定标记为 `deterministic_sha256_preprocessing:not_neural_hash`
   - README / SECURITY / 设计文档已记录当前不声称 SHA-256 或 hash-to-challenge 是神经电路
21. F6 端到端 artifact validation 已完成第一版：
   - `experiments/end_to_end_validation.py` 可离线读取正向 batch summary 与真实服务负向 runner 产物
   - 正向验收会区分 baseline `runtime_auth_enabled=false` 与 PQ-CAN `runtime_auth_enabled=true`
   - 正向验收要求所有任务 success 且 gate reject count 为 0
   - 真实负向验收要求所有场景通过、expected/observed reason 一致、没有 local agent 副作用
   - 已用 `2026-05-27` baseline/PQ-CAN summary 与 `2026-05-31` real-negative run artifact 进行 smoke 校验，结果 `passed=true`
22. C2 token reuse / invalidation 并发风险已完成第一阶段修复：
   - `saga/agent.py` 新增 active / received token 原子消费 helper
   - `receive_conversation(...)` 与 `initiate_conversation(...)` 不再把“校验 token”和“扣减 quota”拆成两个锁外步骤
   - token quota 在同一把锁内校验并扣减，避免两个并发会话同时通过 quota=1 的检查
   - token 失效 helper 改为幂等 `pop(...)`，避免并发结束路径触发 `KeyError`
   - 测试覆盖：
     - active token 并发消费只有一个成功
     - received token 并发消费只有一个成功
     - receiving-side 并发会话共用 quota=1 时只有一个进入 `local_agent.run()`
23. C4 OTK 签名绑定 AID 已完成：
   - `saga/common/crypto.py` 新增 domain-separated canonical OTK payload helper
   - user 注册与 refresh OTK 都签名 `aid + OTK`，不再签 raw OTK bytes
   - Provider 注册与 refresh OTK 均按同一 payload 验签
   - initiating-side 使用 provider 返回 OTK 前也验证同一 AID-bound payload
   - 旧 raw OTK-only 签名和跨 AID 签名均会 fail closed
   - receiving-side 本地 OTK 消费已抽成 `_consume_local_otk(...)`，并测试并发下同一 OTK 只能消费一次

### 当前下一步

下一步建议直接执行：

1. 按用户指定优先级进入 SAGA 正确性：
   - C5/C6 已完成；后续只需保持两层内核边界不回流
2. 然后进入执行层安全补强：
   - 不继续扩大共享文件目录方案；`FileReplayStateStore` 只作为 local/dev/test backend 保留
   - 将当前裸 `replay_state_dir` 配置收敛为显式 `ReplayStoreConfig`，避免共享文件目录看起来像 production-ready 安全后端
   - 如需继续 replay 方向，下一步应接入真实 strongly consistent backend（例如 Redis/DB adapter）并保留同一 `ReplayStateStore.reserve_request(...)` 原子语义
   - opt-in 真实服务负向 runner 可再实际重跑 `--scenario all`，刷新 8 个场景的真实运行产物
3. E8 `CNN + Ring/Module-LWE` 路线评估暂后置，除非用户重新切回论文架构主线。
4. 后续如需继续 ML-DSA 方向，应新增显式 backend 注入入口，而不是复用 toy config-driven helper。

API cost 目前不从价格表估算；只有模型后端诊断记录显式提供 usage/cost 字段时才会进入统计。

当前环境注意事项：

- 本轮真实测试结束时已关闭 `MongoDB / CA file server / Provider / Raj listener`；最新检查未发现遗留 `mongod / http.server / provider.py / schedule_meeting.py / expense_report.py / create_blogpost.py / batch_run.py` 进程。
- 本轮为了修复 preflight，重新注册了 Emma/Raj baseline 用户与 agents。
- 两个旧 calendar agent 证书已重命名为：
  - `saga/user/emma_johnson@gmail.com:calendar_agent/agent.crt.stale-20260516`
  - `saga/user/raj.sharma@gmail.com:calendar_agent/agent.crt.stale-20260516`
- 工作区包含生成凭据、实验结果和本地 DB 状态变更；不得自动 push 到主开发分支。

### 当前结束前固定动作

除非明确阻塞，每次结束前都执行：

1. 更新本工作文档。
2. 检查 `git status --short`。
3. 整理当前 checkpoint 摘要与待提交文件列表。
4. 形成本地 checkpoint；若未命中敏感路径，则推送到 `backup/<current-branch>`。
5. 在工作日志中记录：
   - 本次变更目的
   - 是否形成了本地 checkpoint
   - 是否成功推送备份分支
   - 若失败，失败原因是什么

## 8. 工作日志

### 2026-06-01 Shared Replay Store Session

目标：

- 继续执行层安全补强：把本地 replay marker 机制抽象为可共享 / 可替换的 replay 状态后端。

已做工作：

- 更新 `saga/execution_gate.py`：
  - 新增 `ReplayStateStore` 协议，要求实现 `load_consumed_request_ids(...)` 与原子 `reserve_request(...)`
  - 新增 `FileReplayStateStore`，以共享目录中的独占 marker 文件保存 consumed envelope digest
  - `SignedRequestExecutionGate` 支持显式传入 `replay_state_store`
  - 保留 `replay_state_dir` 兼容路径，并在内部映射到 `FileReplayStateStore`
  - 同时配置 `replay_state_dir` 与 `replay_state_store` 时拒绝，避免 replay 事实源分裂
- 更新 `saga/config.py` / `saga/agent.py`：
  - `ToyRuntimeAuthConfig` 新增可选 `replay_state_dir`
  - config-driven runtime auth 会优先使用显式共享目录；未配置时继续默认使用 `<agent workdir>/audit/replay/`
- 更新测试：
  - `tests/test_execution_gate.py` 覆盖共享 store 跨 gate 实例 replay 拒绝、目录/store 互斥和写入失败 fail-closed
  - `tests/test_execution_gate_factory.py` 覆盖 factory 传入共享 replay store
  - `tests/test_agent_runtime_auth.py` 覆盖 config `replay_state_dir` 让不同 local workdir 共享 replay 状态
- 更新 `README.md`、`SECURITY.md`、`SAGA_PQ_CAN_DESIGN.md` 与本文档：
  - 记录 `replay_state_dir` 配置方式
  - 明确 `FileReplayStateStore` 是本地 / 共享文件系统研究原型
  - 完整多主机一致性仍需外部 strongly consistent backend 实现 `ReplayStateStore`
  - 后续真实场景建议把裸 `replay_state_dir` 收敛为 `ReplayStoreConfig`，并新增 Redis / SQL 这类强一致后端 adapter；共享文件目录只保留为 local/dev/test backend

已验证：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_agent_runtime_auth.py tests/test_execution_gate_factory.py` -> `45 passed`
- `.venv/bin/python -m pytest -q tests/test_runtime_auth_configs.py` -> `2 passed`
- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_agent_runtime_auth.py tests/test_execution_gate_factory.py tests/test_runtime_auth_configs.py` -> `47 passed`
- `.venv/bin/python -m pytest -q` -> `247 passed, 24 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `25 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `29 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

本轮新增 / 修改的共享 replay store 相关范围：

- `README.md`
- `SAGA_PQ_CAN_DESIGN.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `saga/agent.py`
- `saga/config.py`
- `saga/execution_gate.py`
- `tests/test_agent_runtime_auth.py`
- `tests/test_execution_gate.py`
- `tests/test_execution_gate_factory.py`

当前工作区仍包含上一轮未提交的执行层安全补强文件：

- `experiments/real_negative_runner.py`
- `tests/test_real_negative_runner.py`
- `tests/test_kernel_boundaries.py`

阻塞 / 风险：

- 尚未重跑 opt-in 真实服务负向 runner 的 8 场景 artifact。
- 尚未接入 Redis / DB 这类真实强一致 replay 后端；当前只是共享目录原型与 adapter 边界。
- 真实部署路线不建议继续扩大共享文件目录方案；下一轮应把配置面从裸 `replay_state_dir` 调整为显式 replay store backend 选择。
- `git status --short` 显示当前工作区仍有上述本轮与上一轮源码 / 测试 / 文档改动；未发现本次改动涉及 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本轮按用户要求准备将当前项目状态同步到 `origin/repro-local` 与 `origin/backup/repro-local`。

### 2026-06-01 Replay Persistence And Real-Negative Scope-Probe Session

目标：

- 接续 C5/C6 之后的执行层安全补强：持久化 replay 防护，并扩展 opt-in 真实服务负向 runner 的 tool/memory/delegation scope-probe 场景。

已做工作：

- 更新 `saga/execution_gate.py`：
  - `SignedRequestExecutionGate` 新增可选 `replay_state_dir`
  - `consume_request(...)` 在执行路径中把已消费 envelope digest 写成本地 marker
  - 新 gate 实例会从 marker 目录恢复已消费 request id
  - replay marker 写入失败时以 `replay_state_persistence_failed` fail-closed
- 更新 `saga/agent.py`：
  - toy runtime auth helper 默认使用 `<agent workdir>/audit/replay/` 作为 replay 状态目录
  - `Agent.__new__` 测试 shell 缺少 workdir 时保持内存态兼容
- 更新 `experiments/real_negative_runner.py`：
  - 真实服务负向场景从 5 个扩展到 8 个
  - 新增 `unauthorized_tool_scope`、`unauthorized_memory_write`、`unauthorized_delegation`
  - scope-probe 场景先合法进入 prompt，再由记录型 local agent 尝试未签名下游动作
  - 判定口径为 expected local denial reason、local prompt run count 为 1、protected side-effect count 为 0
- 更新测试：
  - `tests/test_execution_gate.py` 覆盖跨 gate 实例 replay marker 恢复和 replay 状态写入失败 fail-closed
  - `tests/test_real_negative_runner.py` 覆盖 8 场景清单、scope-probe payload、listener `--scope-probe` 命令和 query 判定
- 更新 `SECURITY.md` 与本文档：
  - 记录本地 replay 持久化安全语义
  - 记录真实服务负向 runner 的 8 场景与 scope-probe 判定口径
  - 明确分布式 / 多主机共享 replay 状态仍属于后续工作

已验证：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_agent_runtime_auth.py tests/test_execution_gate_factory.py` -> `41 passed`
- `.venv/bin/python -m pytest -q tests/test_real_negative_runner.py` -> `11 passed, 3 subtests passed`
- `.venv/bin/python -m pytest -q tests/test_real_negative_runner.py tests/test_negative_injection_runner.py tests/test_execution_gate.py` -> `44 passed, 3 subtests passed`
- `.venv/bin/python experiments/negative_injection_runner.py --output-dir /tmp/saga-negative-runner-runtime-smoke` -> `14/14` PASS
- `.venv/bin/python -m pytest -q` -> `243 passed, 24 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `25 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `29 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_DESIGN.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/real_negative_runner.py`
- `saga/agent.py`
- `saga/execution_gate.py`
- `tests/test_execution_gate.py`
- `tests/test_real_negative_runner.py`
- `tests/test_kernel_boundaries.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动 opt-in 真实服务 runner，未生成新的 `experiments/runs/` 真实运行 artifact。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；尝试 `git add ...` 时因 `.git/index.lock` 位于只读文件系统而失败：
  - `fatal: Unable to create '/home/kali/saga/.git/index.lock': Read-only file system`
- 本次不自动推送主开发分支；如需备份，只能推送到 `backup/repro-local`。

### 2026-04-30 Session 1

目标：

- 判断在实现 “LWE 签名 + CNN/DNN 认证神经元” 之前，SAGA 需要先复现到什么程度。
- 生成一份可持续维护的工作文档/工作日志，作为后续所有会话的衔接主线。

已做工作：

- 阅读并对照：
  - `AGENTS.md`
  - `SAGA_PQ_CAN_DESIGN.md`
  - `README.md`
  - `REPRO_GAP_CHECKLIST.md`
  - `REPRO_TASK_PLAN.md`
  - `saga/agent.py`
  - `saga/provider/provider.py`
  - `saga/user/user.py`
  - `saga/common/contact_policy.py`
- 确认了设计接入原则：
  - PQ-CAN 不是整体替换 SAGA，而是接在 receiving agent middleware 中
  - 最终判定必须是 `allow = saga_token_valid AND can_accept`
- 确认了仓库现状：
  - lifecycle 接口并非完全缺失，`update_policy` / `deactivate_agent` / `refresh_otks` 已存在
  - 当前仓库还没有 PQ-CAN 代码与 `tests/` 目录
- 新建本工作文档，作为后续继续工作的统一入口
- 确认仓库存在 GitHub 远程：
  - `origin = https://github.com/cyd56-ops/saga.git`
- 确认当前工作区已存在大量已修改和未跟踪文件，因此需要把“会话结束前同步 GitHub”写成显式流程，而不是隐含假设

结论：

- 当前最合适的策略不是先做“论文级全量复现”，而是先做到：
  - 主协议链路可跑通
  - 接入点明确
  - 最小测试基线存在
- 之后再开始 LWE/PQ + CAN 改造

未完成：

- 尚未实际运行 CA / Provider / user / agent 主链路
- 尚未创建 `tests/`
- 尚未实现任何 PQ-CAN 模块

下次会话建议：

- 从 Phase 0 的环境与主链路验证开始

GitHub 同步状态：

- 本次仅更新了工作文档规则，尚未执行提交与推送。
- 后续如果会话目标包含实际代码工作，结束前应按本文档执行 checkpoint 提交与推送。

### 2026-04-30 Session 2

目标：

- 整顿当前工作区，但不影响仓库目录之外的任何文件。

已做工作：

- 审查了当前 `git` 工作区，区分出：
  - 少量真实源码改动
  - 大量由换行符漂移造成的已跟踪噪音
  - 本地 Mongo / Codex 运行目录
- 恢复了绝大多数非实质性的已跟踪噪音改动，仅保留：
  - `.gitignore`
  - `saga/agent.py`
  - `saga/provider/provider.py`
  - `saga/user/user.py`
  - `saga/common/contact_policy.py`
  - 对应 attack model 文件
- 将以下本地目录加入忽略规则：
  - `.codex`
  - `.mongodb/`
  - `.mongodata/`
- 统一了保留源码文件的换行风格，压缩 diff 体积。

结果：

- 工作区已从“整仓大面积脏状态”收敛为“少量可解释的源码改动 + 项目级未跟踪文档”。
- 当前未跟踪但仍保留的文件主要是项目文档与材料，不再夹杂本地 Mongo 目录噪音。

阻塞 / 注意事项：

- `git restore` 在当前环境中需要对 `.git` 写锁；本次为完成仓库内整顿使用了仓库级 `git` 写权限。
- 仍有若干未跟踪项目文档存在，后续需要在合适时机决定哪些纳入版本库：
  - `AGENTS.md`
  - `REPRO_GAP_CHECKLIST.md`
  - `REPRO_TASK_PLAN.md`
  - `SAGA_PQ_CAN_DESIGN.md`
  - `SAGA_PQ_CAN_WORKLOG.md`
  - `paper/`
  - `saga/AGENTS.md`

下次会话建议：

- 直接从 Phase 0 的基线运行验证开始，不需要再重复做工作区噪音清理。

### 2026-04-30 Session 3

目标：

- 启动 Phase 0，验证当前环境下 SAGA 主链路到底能跑到哪一步。

已做工作：

- 验证了运行前提：
  - `python3 --version = 3.11.9`
  - 核心 Python 依赖可导入：`yaml`、`simple_parsing`、`cryptography`、`requests`、`flask`、`flask_pymongo`、`flask_bcrypt`、`flask_jwt_extended`、`smolagents`
  - `config.yaml` 使用本地回环地址：
    - CA: `http://127.0.0.1:8000`
    - Provider: `https://127.0.0.1:5000`
  - 系统 `mongod` 不在 PATH，但仓库内存在可用二进制：
    - `.mongodb/mongodb-linux-x86_64-ubuntu2204-8.0.12/bin/mongod`
- 启动并验证了本地基线服务：
  - repo-local MongoDB
  - `python3 -m http.server 8000` 作为 CA 文件服务
  - fresh Provider 实例，使用临时 workdir `/tmp/saga-provider-phase0-utc2`
- 发现并定位了一个真实阻塞 bug：
  - `saga/common/crypto.py` 中 provider/user/agent 证书使用本地 naive `datetime.now()`
  - 在当前 `Asia/Shanghai` 环境下，这会把 `not_valid_before` 写成未来 UTC 时间
  - 导致 TLS 校验失败：`certificate is not yet valid`
- 已修复该问题：
  - 为证书时间统一改用 UTC aware 时间戳
- 发现并处理了一个本地材料问题：
  - `saga/ca/ca.crt` 曾为空文件
  - 已通过 `python3 generate_credentials.py ca saga/ca/` 重新生成
- 跑通了最小主链路：
  - `user register`
  - `login`
  - `register_agent`
  - 第二个 user / agent 注册
  - `Agent.listen()`
  - `Agent.connect()`
  - `/access` -> token issuance -> TLS conversation -> token invalidation

本次验证使用的最小本地测试身份：

- `phase0b_20260430@mail.com:phase0_agent`
- `phase0c_20260430@mail.com:phase0_agent`

结论：

- Phase 0 已达到目标：当前仓库的最小 SAGA 基线在本环境下是可跑通、可验证的。
- 当前最优先工作已从“环境是否能跑”切换为“补最小测试基线”。

新增已确认问题：

- `JWT_SECRET_KEY` 当前仍使用短字符串 `supersecretkey`，运行时会触发 `InsecureKeyLengthWarning`。
- 该问题不会阻塞 Phase 0，但应纳入后续安全清理或配置化工作。

下次会话建议：

- 进入 Phase 1，先建 `tests/` 骨架，再把本次跑通的主链路逐步转成自动化测试。

GitHub 同步状态：

- 已完成 `git status` 检查并确定本次 checkpoint 范围。
- 已配置仓库本地 Git 身份：
  - `user.name = cyd56-ops`
  - `user.email = yandachen56@gmail.com`
- 已生成本地 checkpoint commit：
  - `52c29e3 checkpoint: complete phase 0 baseline verification`
- 推送到 `origin/repro-local` 失败，原因：
  - `fatal: could not read Username for 'https://github.com': No such device or address`
- 结论：
  - 本地 checkpoint 已落地
  - 远端 GitHub 同步仍被认证问题阻塞

### 2026-04-30 Session 4

目标：

- 把当前仓库的 GitHub 同步方式从 HTTPS 改成 SSH。

已做工作：

- 将当前仓库 `origin` 从 HTTPS 改为 SSH：
  - 旧：`https://github.com/cyd56-ops/saga.git`
  - 新：`git@github.com:cyd56-ops/saga.git`
- 确认当前分支：
  - `repro-local`
- 确认当前本地提交头：
  - `71ede67 log: record github push auth blocker`

当前结果：

- `origin` 已经切换为 SSH。
- `repro-local` 目前仍未建立 upstream。
- 本次顺序重试 `git push -u origin repro-local` 时，会话被中断，因此本次退出前不能确认远端 push 是否成功。
- 当前 `git branch -vv` 仍显示：
  - `repro-local 71ede67 ...`
  - 没有 `[origin/repro-local]` upstream 标记

结论：

- SSH remote 切换已完成。
- 远端同步状态仍需在下次会话开始时优先确认。

下次会话建议：

1. 先执行：
   - `git remote -v`
   - `git branch -vv`
   - `git push -u origin repro-local`
2. 若 SSH push 失败，继续定位：
   - 本机是否存在可用 SSH key
   - GitHub 账户是否已登记该公钥
   - 是否需要 `ssh -T git@github.com` 验证
3. 只有在远端同步状态明确后，再进入 Phase 1。

GitHub 同步状态：

- 本地 remote 已改为 SSH。
- 本地分支尚未确认与远端 `origin/repro-local` 建立跟踪关系。
- 当前工作区除 `paper/` 外是干净的。

### 2026-04-30 Session 5

目标：

- 按“当前工作焦点”进入 Phase 1，补最小自动化测试基线。

已做工作：

- 新增测试目录与包初始化：
  - `tests/`
  - `tests/security/`
  - `tests/integration/`
- 新增 `contact_policy` 单元测试：
  - `tests/test_contact_policy.py`
  - 覆盖 `check_aid()`、`check_rulebook()`、`aid_specificity()`、`match()`
  - 覆盖 most-specific rule、equal-specificity first-win、blocklist `budget=-1`、bad AID
- 新增 token 校验与失效清理测试：
  - `tests/security/test_token_validation.py`
  - 覆盖 initiating-side token 校验
  - 覆盖 received-side token 校验
  - 覆盖 expired / zero-quota / PAC mismatch / dangling mapping cleanup
  - 显式保护 `retrieve_valid_token()` 不回退到会重入加锁的公开校验路径
- 新增最小 baseline integration test 骨架：
  - `tests/integration/test_baseline_agent_flow.py`
  - 覆盖 store -> validate -> retrieve -> invalidate 的轻量 token 生命周期
  - 覆盖 `lookup()` 当前明确抛出 `NotImplementedError`
- 确认并记录了两个当前代码事实：
  - `contact_policy.match()` 现实现与“更高 specificity 优先、同 specificity 首个命中优先”一致
  - `lookup()` 已不是半成品调用路径，而是显式的 compatibility shim
- 补充做了 Phase 2 预审计：
  - 主实现与攻击模型镜像代码中的 received-token 路径都已使用 `_received_token_is_valid_unlocked()`，未再看到旧的“锁内重入公开校验”结构
  - OTK 注册、Provider 验签、initiating agent 使用 OTK 前验签这三处当前都只绑定 `otk` bytes，尚未绑定 `aid`
- 为满足仓库测试命令，安装了 repo-local `.venv` 内的 `pytest`

测试结果：

- `python3 -m unittest discover -s tests -q`：通过，`21` 个测试
- `python3 -m unittest discover -s tests/security -q`：通过，`10` 个测试
- `python3 -m unittest discover -s tests/integration -q`：通过，`2` 个测试
- `.venv/bin/python -m pytest -q`：通过，`21 passed`
- `.venv/bin/python -m pytest -q tests/security`：通过，`10 passed`
- `.venv/bin/python -m pytest -q tests/integration`：通过，`2 passed`

结论：

- Phase 1 已完成。
- 当前仓库已具备最小自动化测试基线，后续可以直接进入 Phase 2 做协议正确性确认。

阻塞 / 注意事项：

- 系统 `python3` 默认环境没有安装 `pytest`，因此仓库规定的 `pytest` 验收命令本次通过 `.venv/bin/python -m pytest ...` 执行。
- 本次只补了轻量 integration skeleton，还不是 CA / Provider / TLS 端到端集成 harness。
- 当前 `git status` 仍包含未跟踪 `paper/`，会话结束前如需提交必须明确排除或说明其不纳入本次 checkpoint。

下次会话建议：

1. 进入 Phase 2，优先确认 token reuse / invalidation 并发风险是否仍存在于主实现与攻击模型镜像代码。
2. 评估 OTK 签名绑定 `aid` 的改造范围，决定是否在进入 PQ 抽象前先修协议语义。

GitHub 同步状态：

- 已完成本次 `git status --short` 检查。
- 已生成本次 checkpoint commit：
  - `02ae6c5 test: add baseline regression suite`
- 已确认 `git push -u origin repro-local` 成功，`repro-local` 已建立对 `origin/repro-local` 的跟踪关系。
- 已将本次 checkpoint push 到 `origin/repro-local`。

### 2026-05-02 Session 6

目标：

- 按工作文档继续推进，从 Phase 2 过渡到 Phase 3。
- 在不改动现有 SAGA 主链路行为的前提下，先落地统一签名抽象和最小研究用实现。

已做工作：

- 复查了当前工作文档、设计文档和代码实际状态，确认：
  - `token` 死锁问题在主实现和攻击模型镜像里都已改成 `_received_token_is_valid_unlocked()` 路径
  - 当前无新的锁重入结构性阻塞
  - `OTK` 签名仍只绑定 `otk` bytes，尚未绑定 `aid`
- 新增 `pq/` 包：
  - `pq/signature_scheme.py`
  - `pq/toy_lwe.py`
  - `pq/mldsa_adapter.py`
  - `pq/__init__.py`
- 新增统一接口：
  - `KeyPair`
  - `SignatureScheme`
- 实现了 `ToyLWESignatureScheme`：
  - 明确标注 `non-production`
  - 使用确定性 seed 生成测试 key pair
  - 提供 `keygen()` / `sign()` / `verify()` 三个接口
  - 仅用于研究 wiring 与回归测试，不用于真实认证
- 实现了 `MLDSAAdapter` stub：
  - 当前未接入外部 backend
  - 默认 fail-closed，调用时明确抛出错误
- 新增测试：
  - `tests/test_toy_lwe.py`
  - 覆盖 round-trip、message tamper、signature tamper、deterministic keygen、adapter fail-closed

测试结果：

- `.venv/bin/python -m pytest -q tests/test_toy_lwe.py`：通过，`5 passed`
- `.venv/bin/python -m pytest -q tests/security`：通过，`10 passed`
- `.venv/bin/python -m pytest -q tests/integration`：通过，`2 passed`
- `.venv/bin/python -m pytest -q`：通过，`26 passed`

阻塞 / 注意事项：

- 当前 shell 中没有 `python` 命令，直接执行 `python -m pytest -q` 会失败：`python: command not found`
- 当前会话仍未实现 canonical request context
- 当前会话仍未修改 OTK 签名绑定语义，因此相关协议行为保持原样
- `ToyLWESignatureScheme` 是研究用 toy 方案，必须继续保持非生产定位

下次会话建议：

1. 在签名抽象之上实现 canonical request context。
2. 决定 OTK 是否升级为绑定 `aid + OTK`，并评估是否需要兼容旧注册材料。
3. 若上述两项没有新阻塞，再进入 `neural/` 的 STEP/RECT/MASK 实现。

GitHub 同步状态：

- 已完成本次 `git status --short` 检查。
- 本次 checkpoint commit：
  - `8da5892 feat: add toy pq signature abstraction`
- 已成功推送到：
  - `origin/repro-local`
- 当前仍保留未跟踪目录：
  - `paper/`

### 2026-05-07 Session

目标：

- 根据最新设计共识，更新工作文档中的目标、阶段计划、任务看板与当前焦点。
- 将 PQ-CAN 的定位从“receiving middleware 单点接入”收紧为“执行层准入控制”。

已做工作：

- 重新核对了当前代码状态与工作文档，确认：
  - `SAGA` 基线、生命周期接口、最小测试基线、`pq/` 签名抽象已落地
  - `PQ-CAN` 的 `neural/`、canonical request context、执行层 gate 仍未开始
- 重新运行并确认当前测试结果：
  - `.venv/bin/python -m pytest -q` -> `26 passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `10 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `2 passed`
- 将“分层协作”设计写回工作文档：
  - `SAGA` 负责协议层访问控制
  - `PQ-CAN` 负责执行层访问控制
  - 最终约束改写为 `allow = protocol_allow AND execution_allow`
- 将 Phase 3 明确为 canonical request envelope 设计阶段，并补充候选字段：
  - `sender_aid`
  - `receiver_aid`
  - `token_digest`
  - `session_id`
  - `turn_id`
  - `issued_at`
  - `expires_at`
  - `action_scope`
  - `message_digest`
  - `pq_signature`
- 将 Phase 5 从“middleware 集成”改写为“执行层集成”，明确首批 gate 接入点：
  - `receive_conversation() -> local_agent.run()`
  - `memory`
  - `tool executor`
  - `delegation chain`
- 更新 `SAGA_PQ_CAN_DESIGN.md`，使其与新分层方案一致：
  - 把“middleware 单点 gate”改写为“协议层准入 + 执行层准入”
  - 将 request context 收紧为 execution-oriented `request_envelope`
  - 新增“最小保留 SAGA 内核”章节
  - 明确 `experiments/`、`proofs/`、`saga/attack_models/`、大部分 `agent_backend/` 当前可移出主线关键路径
- 新增 `saga/messages.py`：
  - 实现 `RequestEnvelope`
  - 实现 canonical JSON 编码
  - 实现时区归一化与 `action_scope` 校验
  - 实现基于 token/message digest 的 envelope builder
- 新增 `tests/test_encoding.py`：
  - 覆盖 deterministic encoding
  - 覆盖时区归一化
  - 覆盖非法 `action_scope`
  - 覆盖非法 AID
  - 覆盖 naive timestamp 拒绝
- 重新运行测试，确认新增编码模块未破坏基线：
  - `.venv/bin/python -m pytest -q tests/test_encoding.py` -> `6 passed`
  - `.venv/bin/python -m pytest -q` -> `32 passed`
- 新增 `neural/` 最小实现：
  - `neural/shamir_layers.py`
  - `neural/verifier_wrapper.py`
  - `neural/can.py`
- 新增 `saga/execution_gate.py` 与 `Agent` 侧接入点：
  - `Agent` 新增可选 `execution_gate`
  - `receive_conversation()` 在 `local_agent.run()` 前调用 execution gate
  - 默认未配置 gate 时保持原有行为
- 新增 Shamir/CAN 相关测试：
  - `tests/test_shamir_layers.py`
  - `tests/test_can.py`
  - `tests/security/test_real_valued_rejection.py`
  - `tests/security/test_boundary_values.py`
- 扩展集成测试：
  - `tests/integration/test_baseline_agent_flow.py` 新增 execution gate 拒绝时不会进入 `local_agent.run()` 的覆盖
- 明确并固化了当前 hard gate 边界语义：
  - `STEP_1_3` 在 `1/3` / `2/3` 处给出硬值
  - 但完整 hard gate 只承诺保留二进制输入
  - 非二进制边界点仍可由 `MASK` 拒绝
- 重新运行仓库要求的测试命令：
  - `.venv/bin/python -m pytest -q` -> `50 passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `16 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `3 passed`
- 明确了真实测试栈的启用阈值：
  - 不要求先完成全部 PQ-CAN
  - 但至少要求 `request_envelope / pq_signature` 已正式进入消息格式
  - receiving-side execution gate 已真实校验这些字段
  - `local_agent.run()` 前已形成最小 end-to-end 闭环
  - 满足这些条件后再接入真实 `smolagents`/模型栈

结果：

- 工作文档现已与当前设计一致，不再把 PQ-CAN 简化为只在 receiving middleware 上做一次门控。
- 设计文档现已与工作文档对齐，并且明确了“最小 SAGA 内核优先、非主线目录可延后”的范围。
- canonical request envelope 已不再停留在文档层，而是有了最小可测试实现。
- `STEP_1_3 / RECT_1_3 / MASK` 和最小 toy `CAN` 也已不再停留在文档层，而是有了独立实现与测试。
- receiving-side 已有 execution gate 入口，执行层集成不再是纯计划项。
- 后续实现顺序也更清晰：
  - 先固定最小 SAGA 内核边界
  - 再收紧 canonical request envelope 语义
  - 再把当前 toy `CAN` 从 `local_agent.run()` 前扩展到 `memory / tool / delegation`

阻塞 / 注意事项：

- 本次已经更新工作文档、设计文档，并新增最小 envelope 实现与测试。
- `OTK` 是否升级为绑定 `aid + OTK` 仍未决策。
- 用户本次要求“先做到这，更新工作文档然后退出”，因此本次在文档收尾后停止，不继续推进真实测试栈接入。
- 当前 `RequestEnvelope` 还未接入实际消息格式，仍未随网络消息传输。
- 当前 `CAN` 虽已有 receiving-side 入口，但还未真正消费 `request_envelope / pq_signature`。
- 当前 execution gate 只覆盖 `local_agent.run()` 前入口，尚未覆盖 `memory / tool / delegation`。

下次会话建议：

1. 决定 `action_scope` 是否需要在第一版细分出更多 scope。
2. 将 `request_envelope / pq_signature` 真正接入消息格式，并让当前 toy `CAN` 消费这些字段。
3. 在形成最小真实闭环后，再接入真实 `smolagents`/模型栈做第一轮真实验证。

GitHub 同步状态：

- 已执行 `git status --short` 检查并记录当前工作区状态。
- 本次未提交、未推送。
- 原因：用户要求先更新工作文档后退出，本次按用户要求在 checkpoint 前停下。

### 2026-05-08 Session

目标：

- 按工作文档继续推进，把 `request_envelope / pq_signature` 真正接入实际消息格式。
- 让 receiving-side execution gate 不再只是接口，而是真正消费已签名 envelope 与 toy `CAN`。

已做工作：

- 扩展 `saga/messages.py`：
  - 为 `RequestEnvelope` 增加 canonical JSON 字符串输出
  - 新增 `parse_request_envelope()`，用于把 JSON 字符串 / bytes / mapping 统一解析回受校验的 envelope
- 扩展 `saga/execution_gate.py`：
  - 新增 `SignedRequestExecutionGate`
  - 该 gate 以 fail-closed 方式执行以下检查：
    - `request_envelope` 必须可解析
    - `sender_aid / receiver_aid / action_scope` 必须与 transport request 一致
    - `token_digest / message_digest` 必须与当前消息匹配
    - envelope 必须处于有效时间窗内
    - 分离签名必须在受信发送方公钥下经当前 toy `CAN` 验证通过
- 扩展 `saga/agent.py`：
  - 为会话消息新增 `action_scope`
  - 为 conversation payload 新增统一构造路径
  - 当 agent 配置了 PQ 签名方案与 secret key 时，发送消息会自动附带：
    - `request_envelope`
    - `pq_signature`
  - `receive_conversation()` 侧保持先做 SAGA token 校验，再做 execution gate，继续满足：
    - `allow = saga_token_valid AND execution_allow`
  - receiving side 回包也走统一 payload builder，保持消息格式一致
- 新增 / 扩展测试：
  - `tests/test_execution_gate.py`
    - 覆盖有效签名放行
    - 覆盖 message digest mismatch 拒绝
    - 覆盖 expired envelope 拒绝
  - `tests/test_encoding.py`
    - 新增 canonical JSON round-trip 解析覆盖
  - `tests/integration/test_baseline_agent_flow.py`
    - 覆盖 initiating side 会附带 `request_envelope / pq_signature`
    - 覆盖 receiving side 使用真实 `SignedRequestExecutionGate + toy CAN` 时可通过最小闭环并进入一次 `local_agent.run()`
- 更新 `SAGA_PQ_CAN_DESIGN.md`：
  - 新增 signed envelope binding / fail-closed 安全不变量

测试结果：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py`：通过，`3 passed`
- `.venv/bin/python -m pytest -q tests/test_encoding.py`：通过，`7 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py`：通过，`5 passed`
- `.venv/bin/python -m pytest -q`：通过，`56 passed`
- `.venv/bin/python -m pytest -q tests/security`：通过，`16 passed`
- `.venv/bin/python -m pytest -q tests/integration`：通过，`5 passed`

结果：

- `request_envelope / pq_signature` 已不再停留在独立模块，而是进入了实际 conversation message format。
- receiving-side execution gate 已真实消费这些字段，并通过当前 toy `CAN` 做 hard gate 验证。
- `local_agent.run()` 前的最小 end-to-end 闭环已形成，因此“真实测试栈启用阈值”现已满足。

阻塞 / 注意事项：

- 当前签名闭环仍是研究用 toy `ToyLWESignatureScheme`，必须继续保持 non-production 定位。
- 当前受信 PQ 公钥仍通过 runtime 注入方式提供，尚未并入现有 Provider / card / registration 材料分发路径。
- execution gate 目前仍只覆盖 `local_agent.run()` 前入口，尚未覆盖 `memory / tool / delegation`。
- `OTK` 是否升级为绑定 `aid + OTK` 仍未决策。

下次会话建议：

1. 设计并接入 `memory / tool / delegation` 前的 execution gate。
2. 决定第一版 `action_scope` 是否需要细分到 tool identity / memory capability 粒度。
3. 评估 PQ 公钥材料应如何并入现有 agent material / provider 分发路径。
4. 在当前最小闭环基础上接入真实 `smolagents`/模型栈做第一轮验证。

GitHub 同步状态：

- 已执行 `git status --short` 检查。
- 已生成本次 checkpoint commit：
  - `cf487a9 feat: wire signed request envelopes into execution gate`
- 已成功推送到：
  - `origin/repro-local`
- 当前仍保留未跟踪目录：
  - `paper/`

### 2026-05-08 Session 2

目标：

- 继续按科研复现方向推进，把 execution gate 从“消息入口闭环”扩到真实 local tool executor。
- 为第一版 `action_scope` 提供足够表达力，使其能约束到具体 tool identity。
- 清除真实 `smolagents` 栈接入前的一个兼容性阻塞。

已做工作：

- 扩展 `saga/messages.py`：
  - 将 `action_scope` 校验从固定枚举提升为结构化解析
  - 新增：
    - `parse_action_scope()`
    - `action_scope_allows()`
  - 第一版现支持：
    - 宽 scope：`tool_call`
    - 窄 scope：`tool_call:<tool_name>`
  - 其中：
    - `tool_call` 可授权任意具体 tool
    - `tool_call:<tool_name>` 只授权同名 tool
- 扩展 `saga/execution_gate.py`：
  - 新增 `LocalExecutionContext`
  - 新增 `SignedRequestExecutionGate.build_local_execution_context()`
  - 这样 receiving-side 在验过签名 envelope 后，不只是得到布尔 allow / deny，还能把已验证 scope 继续下传到本地执行面
- 扩展 `saga/agent.py`：
  - `receive_conversation()` 在通过 `SignedRequestExecutionGate` 后，会构造并下传 `execution_context`
  - 该 context 会作为 `kwargs` 传给 `local_agent.run()`
- 扩展 `agent_backend/base.py`：
  - 为 `AgentWrapper` 增加 tool-level gate 包装逻辑
  - 当前所有通过 `smolagents` 注册进来的本地工具，都会在真正执行前检查：
    - `execution_context.authorize_action(f"tool_call:<tool_name>")`
  - 若 scope 不匹配，则以 `PermissionError` fail-closed 拒绝执行
  - `run()` 会在本次 agent 执行期间挂载并恢复 `_execution_context`
- 修复真实栈兼容性阻塞：
  - 当前环境中的 `smolagents` 不再导出旧版 `HfApiModel`
  - 已为 `agent_backend/base.py` 增加兼容层：
    - 若旧 `HfApiModel` 不存在，则回退到 `InferenceClientModel`
  - 这样 `agent_backend.base` 现在可在当前环境下成功导入，便于下一步做真实栈验证
- 新增 / 扩展测试：
  - `tests/test_encoding.py`
    - 覆盖 `tool_call:<tool_name>` scope 解析
    - 覆盖宽 / 窄 scope 授权关系
  - `tests/test_execution_gate.py`
    - 覆盖 `LocalExecutionContext` 对 tool-specific descendant scope 的授权
    - 覆盖精确限定的 `tool_call:<tool_name>` 不会放宽到其他 tool
  - `tests/test_agent_wrapper_gate.py`
    - 覆盖 `smolagents` tool 在 scope 匹配时可执行
    - 覆盖 scope 不匹配时 fail-closed 拒绝执行
  - `tests/integration/test_baseline_agent_flow.py`
    - 覆盖 receiving-side 能把已验证 `LocalExecutionContext` 继续传给 `local_agent.run()`

测试结果：

- `.venv/bin/python -m pytest -q tests/test_encoding.py`：通过，`9 passed`
- `.venv/bin/python -m pytest -q tests/test_execution_gate.py`：通过，`5 passed`
- `.venv/bin/python -m pytest -q tests/test_agent_wrapper_gate.py`：通过，`2 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py`：通过，`6 passed`
- `.venv/bin/python -m pytest -q`：通过，`63 passed`
- `.venv/bin/python -m pytest -q tests/security`：通过，`16 passed`
- `.venv/bin/python -m pytest -q tests/integration`：通过，`6 passed`

结果：

- execution gate 已不再只停留在 `local_agent.run()` 前入口，而是进入了真实 `smolagents` tool executor 的最小执行面。
- 第一版 `action_scope` 已具备 tool identity 粒度，可用于研究用的 tool 级授权实验。
- 真实 `smolagents` 栈的一个直接兼容性阻塞已清理，下一步可以更顺畅地进入真实模型 / 工具链验证。

阻塞 / 注意事项：

- 当前 local gate 只覆盖到了 tool executor，`memory / delegation` 仍未接入。
- 当前 tool-level gate 仍是研究原型语义，尚未定义更细的 reject / drop / audit 行为面向真实产品接口。
- `HfApiModel -> InferenceClientModel` 兼容层只解决了导入 / 构造阻塞，不代表真实远端推理链路已验证通过。
- 当前签名闭环仍是研究用 toy `ToyLWESignatureScheme`，必须继续保持 non-production 定位。

下次会话建议：

1. 继续把 `execution_context` 扩到 `memory / delegation`。
2. 在真实 `CodeAgentWrapper` 上做第一轮 smoke test，验证 tool-level gate 会真正拦截未经授权的 tool。
3. 决定 `memory_read / memory_write` 是否也要支持带 qualifier 的 scope。
4. 继续评估 PQ 公钥材料如何并入 Provider / registration 流程。

GitHub 同步状态：

- 已执行本次会话内的规定测试命令。
- 已生成本次 checkpoint commit：
  - `01c45b7 feat: extend execution gate into local tool executor`
- 首次 `git push` 失败：
  - 原因：远端连接被关闭，报错 `Connection closed by 198.18.0.62 port 443`
- 已重试并成功推送到：
  - `origin/repro-local`
- 当前仍保留未跟踪目录：
  - `paper/`

### 2026-05-08 Session 3

目标：

- 不再继续实现，先评估“还需要再做什么工作才能用真实测试栈测试”。
- 将该评估结果写回工作文档，作为下次会话的直接起点。

已做工作：

- 结合当前代码状态、配置文件与工作文档，重新核对了真实测试栈的最小前提。
- 明确了当前已经具备的条件：
  - `request_envelope / pq_signature` 已进入真实消息格式
  - receiving-side execution gate 已真实消费这些字段
  - `local_agent.run()` 前 gate 已形成最小闭环
  - `smolagents` tool executor 前的最小 gate 也已落地
- 明确了进入真实测试栈前仍需补齐的最小缺口：
  - 启动真实基础设施：
    - `MongoDB`
    - `CA`
    - `Provider`
  - 准备真实模型后端凭据：
    - 若沿用现有 `OpenAIServerModel` 配置，则至少需要 `OPENAI_API_KEY`
    - 若改走 Hugging Face 路径，则需要 `HF_TOKEN`
  - 运行真实注册与数据准备流程：
    - 使用 `user.py` 完成 user / agent 注册
    - 生成实际 `agent.json` 材料
    - 为 email / calendar / documents 工具灌入测试数据
  - 新增一条最小真实 smoke harness：
    - 真实创建 `CodeAgentWrapper`
    - 真实创建 `Agent`
    - 真实挂载 `SignedRequestExecutionGate`
    - 验证“被授权 tool 可执行，未授权 tool 被拦截”
  - 在 smoke harness 中手工注入 trusted PQ public key：
    - 当前 PQ 公钥还未并入 Provider / registration 分发路径
    - 因此真实测试第一轮仍需 runtime 注入 trusted key material
- 明确了哪些事项不是“开始真实测试”的硬阻塞：
  - `memory / delegation` gate 尚未落地，但不阻塞第一轮 tool-focused smoke test
  - `OTK` 是否绑定 `aid + OTK` 仍未决策，但不阻塞第一轮真实闭环验证
  - `SECURITY.md` / README 更新不阻塞第一轮真实执行验证

结果：

- 现在距离“开始用真实测试栈做第一轮验证”已经不差大的架构改动。
- 下一步最合适的动作，不是继续抽象设计，而是直接补一条真实 smoke test harness，并把本地基础设施拉起来。

下次会话建议：

1. 启动 `MongoDB`、`CA`、`Provider` 本地基础设施。
2. 准备真实模型凭据并确认选用的模型后端。
3. 跑 user / agent 注册与工具数据 seed。
4. 新增真实 `CodeAgentWrapper + Agent + SignedRequestExecutionGate` smoke harness。
5. 在该 harness 中验证：
   - `tool_call:send_email` 这类被授权 tool 能执行
   - scope 不匹配的 tool 会被真实拦截

GitHub 同步状态：

- 本次仅更新工作文档，不再继续代码实现。
- 本次未提交、未推送。
- 原因：用户明确要求“今天先做到这，更新工作文档然后退出”。

### 2026-05-09

目标：

- 延续“方案二”主线，继续把 execution gate 从 `local_agent.run()` / `tool` 往 `memory / delegation` 方向推进。

已做工作：

- 在 `saga/execution_gate.py` 的 `LocalExecutionContext` 中补充显式 helper：
  - `require_action()`
  - `authorize_tool_call()` / `require_tool_call()`
  - `authorize_memory_read()` / `require_memory_read()`
  - `authorize_memory_write()` / `require_memory_write()`
  - `authorize_delegation()` / `require_delegation()`
- 在 `agent_backend/base.py` 中补充本地执行面 gate helper：
  - `_require_execution_action()`
  - `_read_agent_memory_steps()`
  - `_append_agent_memory_step()`
  - `_require_delegation_permission()`
- 在 `agent_backend/base.py` 中新增第一版 delegation 接口：
  - `set_delegation_handler()`
  - `delegate_to_agent()`
- 在 `saga/agent.py` 中新增 runtime hook 绑定：
  - `_bind_local_agent_runtime_hooks()`
  - `_delegate_to_agent()`
  - 当前默认把 wrapper 内的 delegation 调用落到外层 `Agent.connect(...)`
- 将 `AgentWrapper.run()` 的 `execution_context` 安装时机前移，使初始化阶段的 memory 写入也能被 gate。
- 将 `AgentWrapper._initialize_agent()` 中真实存在的 `agent.memory.steps.append(...)` 改为走 `_append_agent_memory_step()`，不再绕过 `memory_write` gate。
- 保持现有 `tool` 包装走统一执行面判定，同时兼容原有 tool rejection 报错文案。
- 新增并通过相关测试，覆盖：
  - tool gate
  - memory read / write gate
  - delegation gate helper
  - delegation 接口调用 handler
  - Agent runtime hook 会把 delegation handler 绑定到真实 `connect(...)`
  - execution context 的 memory / delegation helper 语义
  - initiating-side agent 初始化时的真实 memory bootstrap 写入会经过 `memory_write` gate

结论：

- 当前 `tool` 已有真实执行路径上的 gate。
- 当前 `memory` 已至少有一个真实写入点走 gate。
- 当前 `delegation` 已有第一版真实接口，并已默认绑定到 `Agent.connect(...)` 这条真实外层通信路径。
- 当前 `memory / delegation` 仍需继续寻找更多真实消费点，尤其是 prompt/backend 中如何显式触发 delegation。
- 下一步应寻找或建立第一版真实 memory / delegation 消费点，而不是继续只堆 helper。

GitHub 同步状态：

- 本次已更新工作文档，并同步了当前状态面板、当前焦点与本次会话记录。
- 本次未提交、未推送。
- 原因：用户明确要求“先做到这里，更新工作文档并退出”。

### 2026-05-09 Session

目标：

- 根据最新共识，把 PQ-CAN 主线从“CNN/DNN 并列探索”收紧为“先 compiled DNN verifier 验证架构，再升级到 CNN + Ring/Module-LWE”。
- 同时确认当前本地 git 分支与远端跟踪关系。

已做工作：

- 复核了当前 `toy_lwe`、`neural/can.py`、`neural/verifier_wrapper.py` 的实现边界，确认：
  - 当前 toy LWE 是一般矩阵结构
  - 更自然的第一步是 fixed `Linear/DNN` 编译，而不是强行做 CNN
  - 当前 `verifier_wrapper` 仍主要是 wrapper 调 `scheme.verify()`，尚未形成真正 compiled DNN verifier
- 将上述结论写回主工作文档：
  - 在“当前阶段目标”中明确 `toy/general-matrix LWE -> compiled DNN verifier -> CNN + Ring/Module-LWE` 的升级顺序
  - 在“当前状态面板”中补充当前 verifier 仍是 wrapper 的事实
  - 将 Phase 4 改写为 `Shamir` 层与 `Compiled DNN CAN`
  - 在任务看板中新增“编译 toy LWE DNN verifier”与“评估 CNN + Ring/Module-LWE 路线”
  - 将“当前工作焦点”改为优先进入 compiled DNN verifier 第一阶段
- 检查了当前 git 分支与远端：
  - 本地分支：`main`、`repro-local`
  - 当前分支：`repro-local`
  - 跟踪关系：
    - `main -> origin/main`
    - `repro-local -> origin/repro-local`

结论：

- 当前正确的研发主线应视为：
  - `repro-local` 上继续推进 SAGA-PQ-CAN 原型与工作文档
  - 先做 compiled DNN verifier 验证架构可行性
  - 再考虑 `CNN + Ring/Module-LWE` 的结构升级
- 当前远端并没有看到自动备份分支 `backup/repro-local` 已成为常态主线；现有实际工作分支是 `repro-local`。

GitHub 同步状态：

- 本次已更新工作文档。
- 本次未提交、未推送。
- 原因：本次任务以整理路线和确认分支状态为主，且工作区当前仍包含 `paper/` 等需谨慎处理的路径。

### 2026-05-09 Compiled DNN Session

目标：

- 按“当前工作焦点”进入 compiled DNN verifier 第一阶段。
- 将 toy/general-matrix LWE 的公开矩阵投影从“wrapper 调 scheme.verify()”推进到第一版固定 `Linear/DNN` 电路实现。

已做工作：

- 为 `ToyLWESignatureScheme` 补充公开 helper：
  - `vector_bytes`
  - `public_matrix()`
  - `challenge_vector()`
  - `decode_public_vector()`
  - `decode_signature_vector()`
- 新增 `neural/compiled_lwe_dnn.py`：
  - `FixedMatrixProjector`
  - `ProjectionTrace`
  - `CompiledToyLWEVerifier`
- 当前 compiled verifier 的边界明确为：
  - 公开矩阵投影编译成固定 `Linear` 行投影
  - challenge 生成仍是确定性显式预处理
  - 模减与最终等式聚合仍是硬门，不伪装成“已完全神经化”
- 将 `CAN` 的 verifier 输入类型收紧为 bit-level verifier 协议，而不只绑定 `SignatureVerifierWrapper`
- 更新 `neural/__init__.py` 导出 compiled verifier 相关符号
- 新增 `tests/test_compiled_lwe_dnn.py`，覆盖：
  - 合法签名通过
  - 篡改签名拒绝
  - compiled verifier 与 `scheme.verify()` 对齐
  - 固定矩阵投影层 `requires_grad=False`
  - `CAN` 可直接消费 compiled verifier

测试结果：

- `.venv/bin/python -m pytest -q tests/test_compiled_lwe_dnn.py` -> `6 passed`
- `.venv/bin/python -m pytest -q tests/test_can.py tests/test_toy_lwe.py` -> `11 passed`
- `.venv/bin/python -m pytest -q tests/security/test_real_valued_rejection.py tests/security/test_boundary_values.py` -> `8 passed`

结论：

- compiled DNN verifier 不再只是文档计划项，第一阶段代码已落地。
- 当前最诚实的表述应是：
  - 已完成“公开矩阵投影 -> 固定 `Linear` 电路”
  - 尚未完成“challenge / 模运算 / 比较器”的进一步电路化
- 这已经足够支撑下一步继续收紧 verifier 电路边界，或评估何时把该 verifier 挂到更真实的执行层路径上。

GitHub 同步状态：

- 本次已更新工作文档。
- 本次尚未提交、尚未推送。
- 将在本次会话结束前统一执行 `git status` 检查、准备 checkpoint 摘要，并决定是否形成新的本地 checkpoint。

### 2026-05-09 Compiled DNN Session 2

目标：

- 继续收紧 compiled toy LWE verifier 的电路边界。
- 将模减、逐系数比较和最终 accept 聚合从内联 Python 逻辑收成显式固定模块。

已做工作：

- 在 `neural/compiled_lwe_dnn.py` 中新增固定硬门模块：
  - `FixedModSubtractor`
  - `FixedEqualityGate`
  - `FixedEqualityAggregator`
- 将 `ProjectionTrace` 扩展为显式记录：
  - `equality_bits`
  - `accept`
- 将 `CompiledToyLWEVerifier.trace_verification()` 改为通过上述固定模块生成：
  - `recovered_public`
  - coordinate-wise equality bits
  - final hard accept bit
- 更新 `neural/__init__.py` 导出新增固定模块
- 扩展 `tests/test_compiled_lwe_dnn.py`，补充覆盖：
  - modular subtractor 的硬模语义
  - equality gate / aggregator 的硬 bit 语义
  - 篡改签名后至少一位 equality bit 归零

测试结果：

- `.venv/bin/python -m pytest -q tests/test_compiled_lwe_dnn.py` -> `9 passed`
- `.venv/bin/python -m pytest -q tests/test_can.py tests/security/test_real_valued_rejection.py tests/security/test_boundary_values.py` -> `14 passed`

结论：

- 当前 compiled toy LWE verifier 已不只是“矩阵投影 compiled”。
- 更准确的阶段描述应为：
  - challenge 生成仍是显式预处理
  - 公开矩阵投影、模减、逐系数比较、最终 accept 聚合已收成显式固定模块
- 下一步最值得继续推进的是：是否需要把 challenge 派生后的更多边界也继续模块化，还是优先把当前 compiled verifier 接到更真实的执行层路径上。

GitHub 同步状态：

- 本次已更新工作文档。
- 本次尚未提交、尚未推送。
- 将在本次会话结束前统一执行完整测试、`git status` 检查与本地 checkpoint 整理。

### 2026-05-09 Execution Gate Compiled Session

目标：

- 将当前 compiled toy LWE verifier 挂到更真实的 execution gate 路径上，而不只停留在独立 verifier/CAN 测试。

已做工作：

- 将 `tests/test_execution_gate.py` 中的 `SignedRequestExecutionGate` 构造改为直接使用：
  - `CAN(CompiledToyLWEVerifier(...))`
- 新增 compiled verifier 路径下的 detached signature 篡改拒绝测试
- 将 `tests/integration/test_baseline_agent_flow.py` 中 receiving-side gate 的关键集成用例改为直接使用 compiled verifier：
  - 合法 signed message 通过后进入 `local_agent.run()`
  - execution context 继续正确传播到 receiving-side 本地执行层

测试结果：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py` -> `9 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py` -> `7 passed`

结论：

- compiled toy LWE verifier 已不再只是独立神经模块或单独 CAN 模块。
- 当前 execution gate 的真实闭环测试已经可以直接消费 compiled verifier。
- 下一步如果继续沿这个方向推进，最自然的工作是：
  - 判断是否给 execution gate 增加更正式的 verifier factory / wiring helper
  - 或继续把 compiled verifier 推进到更多真实 prompt/backend 消费点

GitHub 同步状态：

- 本次已更新工作文档。
- 本次尚未提交、尚未推送。
- 将在本次会话结束前统一执行完整测试与 checkpoint 检查。

### 2026-05-09 Session Wrap-up

目标：

- 结束今天的工作前，把工作文档与本地 Git 状态收敛到便于下次继续的状态。

已做工作：

- 逐步完成并保留了以下本地 checkpoint：
  - `a51a7f1` `checkpoint: stabilize pq-can working tree`
  - `620c996` `feat: add first compiled toy lwe verifier core`
  - `f93677f` `feat: tighten compiled toy lwe hard gates`
  - `e952474` `test: wire compiled verifier into execution gate`
- 本次结束前再次确认：
  - `git status --short` 为空
  - 当前分支为 `repro-local`
  - 当前本地分支相对 `origin/repro-local` 为 `ahead 4`
- 确认工作文档当前已覆盖：
  - compiled verifier 第一阶段
  - hard-gate 深化
  - execution gate 测试闭环接线
  - 当前下一步建议

结论：

- 今天可以在干净工作区上结束，不会给后续会话留下未整理的本地脏状态。
- 下次继续时，应直接从：
  - challenge 生成是否继续下沉
  - execution gate 是否需要 verifier factory / wiring helper
  - prompt/backend 更多真实消费点
  这三项里继续推进。

GitHub 同步状态：

- 今天先形成了本地 checkpoint，随后已额外推送到远端备份分支：
  - `origin/backup/repro-local`
- 当前 `repro-local` 相对 `origin/repro-local` 仍超前多个提交，但机器损坏风险已由备份分支覆盖。
- 当前未把这些提交推回常规开发分支 `origin/repro-local`。

### 2026-05-09 Backup Push

目标：

- 将今天本地领先于 `origin/repro-local` 的 checkpoint 提交备份到远端，降低机器损坏导致的进度丢失风险。

已做工作：

- 审查了待备份的提交范围与文件列表，确认不包含：
  - `paper/`
  - 本地数据库目录
  - 私钥材料目录
  - `.venv/`
  - 运行日志目录
- 已成功执行：
  - `git push origin HEAD:backup/repro-local`

结果：

- 远端已创建：
  - `origin/backup/repro-local`
- 当前本地工作结果已具备远端备份副本。

GitHub 同步状态：

- 备份推送：`成功`
- 备份分支：`backup/repro-local`
- 常规开发跟踪分支 `origin/repro-local` 仍未前移；如需让仓库主开发线与本机一致，后续需再决定是否推送或整理后推送到该分支。

### 2026-05-11 Execution Gate Factory Session

目标：

- 将 execution gate 的当前 toy LWE 装配路径从“测试里手工拼装”收成正式 helper。
- 为后续真实 `smolagents` / 模型栈接入准备稳定的 verifier wiring 入口。

已做工作：

- 在 `saga/execution_gate.py` 中新增：
  - `build_toy_lwe_execution_gate(...)`
  - 内部支持：
    - `verifier_flavor=\"compiled\"`
    - `verifier_flavor=\"wrapper\"`
- 为 helper 增加输入校验：
  - trusted key map 不能为空
  - trusted public key 长度必须一致
  - 空 public key bytes 直接拒绝
- 保持 compiled verifier 路径为默认值，使当前研究主线继续偏向固定 DNN/Linear verifier。
- 新增 `tests/test_execution_gate_factory.py`，覆盖：
  - compiled helper 接受合法请求
  - wrapper helper 接受合法请求
  - 空 trusted key map 拒绝
  - mixed public-key length 拒绝
- 同步修正文档中的过时状态描述：
  - 移除“尚未看到 `neural/`”的旧表述
  - 更新全量测试计数

测试结果：

- `.venv/bin/python -m pytest -q tests/test_execution_gate_factory.py tests/test_execution_gate.py tests/integration/test_baseline_agent_flow.py` -> `20 passed`
- `.venv/bin/python -m pytest -q` -> `92 passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `7 passed`

结论：

- execution gate 的当前 research wiring 已从“测试内联装配”提升为正式 helper。
- 下一步最自然的方向不是继续扩 helper 本身，而是把该 helper 接到更真实的 runtime / agent 初始化入口。

GitHub 同步状态：

- 本次已更新工作文档。
- 已生成本地 checkpoint commit：
  - `ca3ab1e` `feat: add execution gate factory helper`
- 备份推送到 `origin/backup/repro-local` 失败：
  - 首次尝试受当前沙箱/SSH 配置限制影响
  - 提权重试后仍失败：`Connection closed by 198.18.0.110 port 443`
- 结论：
  - 本地 checkpoint 已保留
  - 远端备份本次未成功，需要后续在网络/SSH 条件恢复后重试

### 2026-05-11 Agent Runtime Wiring Session

目标：

- 将 toy LWE execution-auth wiring 再往真实 `Agent` 初始化层推进一步。
- 避免后续实验或真实 `smolagents` 接线时，只能分别手工设置 `pq_signature_scheme / pq_secret_key / execution_gate`。

已做工作：

- 在 `saga/agent.py` 中新增：
  - `enable_toy_lwe_runtime_auth(...)`
- 该 helper 当前会一次性为真实 `Agent` 实例挂上：
  - `pq_signature_scheme`
  - `pq_public_key`
  - `pq_secret_key`
  - `execution_gate`
- 新增 `tests/test_agent_runtime_auth.py`，覆盖：
  - helper 会正确填充 `Agent` 上的 runtime auth 状态
  - 两个 helper 配置过的最小 `Agent` 实例可以：
    - 由发送侧自动构造 signed payload
    - 由接收侧 execution gate 成功授权
  - wrapper verifier flavor 仍可通过同一 helper 走通
- 更新 `README.md`：
  - 补充 research-only toy LWE runtime wiring 的最小示例

测试结果：

- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_execution_gate_factory.py tests/test_execution_gate.py tests/integration/test_baseline_agent_flow.py` -> `23 passed`
- `.venv/bin/python -m pytest -q` -> `95 passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `7 passed`

结论：

- 当前 runtime wiring 已不再停留在：
  - `ExecutionGate` helper
  - 或测试内联装配
- 现在已经有了可直接作用在真实 `Agent` 实例上的第一版 helper。
- 下一步最自然的工作是：
  - 决定是否把该 helper 进一步接入 `experiments/*` 或配置驱动入口
  - 或开始第一轮真实 `smolagents` / 模型栈验证

GitHub 同步状态：

- 本次尚未形成新的本地 checkpoint。
- 当前仍以上一次本地 checkpoint 为基础继续工作。
- 若本次会话结束，需要重新执行 `git status`、整理待提交文件列表，并决定是否形成新的本地 checkpoint。

### 2026-05-11 Config-Driven Runtime Wiring Session

目标：

- 将 research-only toy runtime auth 从“helper 已存在”推进到“真实实验入口可由配置启用”。
- 避免后续实验脚本继续手工插入 PQ-CAN wiring 代码。

已做工作：

- 在 `saga/config.py` 中新增：
  - `ToyRuntimeAuthConfig`
  - `AgentConfig.toy_runtime_auth`
- 在 `saga/agent.py` 中新增：
  - `enable_toy_lwe_runtime_auth_from_config(...)`
  - 会从配置中：
    - 解码 base64 trusted public keys
    - 按 seed 生成 toy LWE key pair
    - 自动调用 runtime helper 挂载 sending-side signing 与 receiving-side gate
- 将以下真实任务入口改成自动消费该配置：
  - `experiments/schedule_meeting.py`
  - `experiments/expense_report.py`
  - `experiments/create_blogpost.py`
- 扩展 `tests/test_agent_runtime_auth.py`：
  - 覆盖 config-driven helper
  - 覆盖非法 base64 trusted key 拒绝
- 更新 `README.md`：
  - 补充最小 `toy_runtime_auth` YAML 示例
  - 说明哪些 experiments 入口会自动启用该配置

测试结果：

- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_execution_gate_factory.py tests/test_execution_gate.py tests/integration/test_baseline_agent_flow.py` -> `24 passed`
- `.venv/bin/python -m pytest -q` -> `112 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `12 passed, 12 subtests passed`

结论：

- 当前 research-only toy runtime auth 已经不是孤立 helper：
  - `ExecutionGate` helper 已有
  - `Agent` runtime helper 已有
  - 配置驱动入口也已打通到真实 experiment entrypoints
- 当前已有可直接拿来跑 experiments 的示例配置：
  - `user_configs/emma_pqcan.yaml`
  - `user_configs/raj_pqcan.yaml`
- 当前已具备入口级回归保证：
  - `experiments/schedule_meeting.py`
  - `experiments/expense_report.py`
  - `experiments/create_blogpost.py`
  - 三者的 `listen/query` 路径都已有本地集成测试验证其会按示例配置装配 PQ-CAN runtime auth
  - 且 receiver-side 对缺签名请求、错误 trusted key 请求均会 fail closed
- 当前 reject/drop/audit 默认行为已更完整：
  - reject：gate 拒绝仍默认终止该次请求进入本地执行
  - audit：本地日志现在会附带稳定 reason，并输出结构化 `AUDIT` 记录，同时追加到 `<agent workdir>/audit/execution_gate.jsonl`
- 当前本地失败路径覆盖已继续扩展：
  - `action_scope_mismatch`
  - `envelope_not_yet_valid`
  - 缺失签名材料
  - trusted key mismatch
- 当前本地结果记录已形成两层产物：
  - agent workdir 级 `audit/execution_gate.jsonl`
  - experiment 级 `experiments/results/<task-name>.jsonl`
- 下一步最自然的工作已收敛为：
  - 直接基于上述示例配置做第一轮真实 experiment 闭环验证
  - 或继续把 research-only toy wiring 替换为更正式的 PQ adapter / verifier 接口

GitHub 同步状态：

- 本次尚未形成新的本地 checkpoint。
- 若本次会话结束，需要重新执行 `git status`、整理待提交文件列表，并决定是否形成新的本地 checkpoint。

### 2026-05-15 Real Stack Bring-Up Session

目标：

- 按 `test_optimized.md` 拉起第一轮真实测试栈。
- 判断是否已经可以正式进入 `Batch 1` 冒烟。

已做工作：

- 确认 `test_optimized.md` 已复制到仓库根目录，并将其作为本轮真实测试执行基线。
- 重新核对真实测试前置条件：
  - `.venv`
  - `OPENAI_API_KEY`
  - `config.yaml`
  - `MongoDB`
  - `CA`
  - `Provider`
  - baseline / PQ-CAN YAML
- 拉起并验证真实基础设施：
  - `MongoDB` 可用
  - `CA` 文件服务可启动
  - `Provider` 可启动
- 检查 Provider Mongo 库状态，确认库为空后，完成 baseline 注册：
  - `emma.yaml`
  - `raj.yaml`
  - 两侧 user / agent 均已成功注册
- 重置并重新灌入工具数据：
  - `experiments/seed_tool_data.py`
- 在真实运行过程中定位并修复多项环境阻塞：
  - `.venv` 缺失 `openai`
  - `.venv` 缺失 `ddgs`
  - `Provider` TLS 证书链与当前 `CA` 不一致
  - `CA` 文件服务直接对 `saga/ca/` 提供文件，导致客户端下载时把 `ca.crt` 自覆盖为 0 字节
  - `saga/agent.py` 在 initiator 侧无条件记录 `agent:llm_backend_init`，会额外抛 `ValueError`
  - `OpenAIServerModel` 默认超时过短，receiver 侧曾出现 `openai.APITimeoutError`
- 为继续真实测试做了两处小型代码修复：
  - `agent_backend/base.py`
    - 为 `OpenAIServerModel` 显式传入 `client_kwargs={"timeout": 60.0}`
  - `saga/common/overhead.py` / `saga/agent.py`
    - 新增 `Monitor.has_run(...)`
    - 仅在存在计时记录时输出 `agent:llm_backend_init`
- 尝试执行 `schedule_meeting` baseline 正向任务多次：
  - initiator / receiver 证书校验成功
  - `Provider /access` 成功
  - token 发放成功
  - socket 建连成功
  - receiver 侧已经进入真实 `CodeAgent` 的 `Step 1`

测试结果：

- `./.venv/bin/python -m pytest -q` -> `112 passed, 12 subtests passed`
- `./.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `./.venv/bin/python -m pytest -q tests/integration` -> `12 passed, 12 subtests passed`
- `./.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_agent_wrapper_gate.py` -> `12 passed`
- `./.venv/bin/python -m pytest -q tests/test_agent_wrapper_gate.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `12 passed, 12 subtests passed`

当前结论：

- 现在已经不是“真实测试环境完全没拉起来”的状态。
- 第一轮真实测试的基础设施、注册、依赖、证书链和最小模型连通性问题已大体清理。
- 当前第一条 `schedule_meeting` baseline 已能进入真实 receiver-side `CodeAgent` 执行阶段。
- 但 `Batch 1` 仍不能正式开始计数：
  - 因为第一条 baseline 正向任务还没有得到 `success=true`
  - 当前 `experiments/results/schedule_meeting.jsonl` 中已有多条失败记录，只能作为排障证据
- 当前失败尚未表现为 PQ-CAN gate reject：
  - receiver-side 没有对应 `execution_gate.jsonl` reject 审计
  - 因此当前主要阻塞仍在 baseline 业务执行链，而不是 execution gate fail-closed 语义

当前最可能失败点：

1. receiver-side OpenAI 调用虽然不再立即超时，但仍然偏慢，导致长时间无结果返回。
2. agent 已进入真实多轮推理，但没有收敛到可执行计划。
3. 本地工具没有被实际调用，或调用前卡在 agent 规划阶段。
4. 工具已调用，但 `schedule_meeting.py` 的成功判定（calendar side effect / oracle）未满足。
5. receiver 返回内容格式或时机仍可能让 initiator 侧无法正常完成对话收尾。

下次会话建议：

1. 只调试 `schedule_meeting.py` baseline。
2. 在 receiver-side 为以下环节补更细日志：
   - `local_agent.run()` 前后
   - 模型首轮返回
   - tool 调用开始/结束
   - 任务成功判定读取的数据
3. 先把 baseline 第一条正向任务跑通，再重新清理 `experiments/results/*.jsonl` 并开始正式 `Batch 1`。
4. 在 baseline 跑通前，不继续正式执行 PQ-CAN 正向与负向场景。

GitHub 同步状态：

- 本次已更新工作文档。
- 本次尚未形成新的本地 checkpoint。
- 本次未推送备份分支。
- 当前工作区除文档更新外，还包含：
  - `agent_backend/base.py`
  - `saga/common/overhead.py`
  - `saga/agent.py`
  - `experiments/results/`
  - `test_optimized.md`
  - `saga/provider/provider.*.selfsigned`

### 2026-05-15 Runtime Diagnostics Session

目标：

- 按“当前工作焦点”继续推进 `schedule_meeting` baseline 排障。
- 为真实 baseline 增加足够细的结构化诊断，而不是继续只看 `Success: False`。

已做工作：

- 新增 `saga/runtime_diagnostics.py`：
  - 提供 local-agent 运行摘要的构造、落盘、读取与汇总
  - 记录 `memory step / tool call / final answer / error step / LLM elapsed`
- 在 `saga/agent.py` 中接入 initiating / receiving 两侧 runtime 诊断：
  - 每次 `local_agent.run()` 后会写入 `<agent workdir>/diagnostics/local_agent_runs.jsonl`
  - 同时输出轻量 `DIAG` 日志，便于现场排障
- 增强 `experiments/schedule_meeting.py`：
  - 为会议 oracle 增加结构化 `evaluate(...)`
  - 输出稳定 `oracle_reason`
  - query 侧会同时汇总 initiator / receiver 的 runtime 诊断摘要
  - query 侧会汇总 receiver 的 execution-gate audit 摘要
  - 结果 JSONL 现可携带上述排障字段
- 扩展并新增测试：
  - `tests/test_runtime_diagnostics.py`
  - `tests/test_schedule_meeting.py`
  - `tests/test_result_logging.py`
  - 保持 `tests/integration/test_experiment_runtime_auth_entrypoints.py` 通过
- 修复一个兼容性回归：
  - 新增诊断最初假设 `llm_monitor` 一定实现 `elapsed()`
  - 后改为在 monitor 不支持时安全记为 `None`
  - 保持对集成测试中轻量 `_NoOpMonitor` 的兼容

测试结果：

- `.venv/bin/python -m pytest -q` -> `117 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `12 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/test_runtime_diagnostics.py tests/test_schedule_meeting.py tests/test_result_logging.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `13 passed, 12 subtests passed`

当前结论：

- 当前“补更细日志”的这一步已经完成。
- 现在可以不再只靠 `schedule_meeting.jsonl` 的 `success=false` 做盲排查，而是直接区分：
  - receiver 是否真的进入了本地 agent 执行
  - 是否产生了 memory steps
  - 是否发生了 tool call
  - 是否走到了 final answer
  - 会议 oracle 具体为何失败
- 因此下一步应从“补日志”切换到“实际跑 baseline 并读取这些诊断”。

阻塞 / 注意事项：

- 本次没有重新实际运行真实 `schedule_meeting` baseline；这仍是下一步。
- 当前工作区仍包含不应自动推送的敏感/生成物：
  - `saga/provider/provider.crt.selfsigned`
  - `saga/provider/provider.key.selfsigned`
  - `saga/provider/provider.pub.selfsigned`
  - `experiments/results/`
- 因命中上述路径，本次不应自动推送备份分支。

GitHub / checkpoint 状态：

- 已执行 `git status --short` 检查。
- 当前可提交的安全代码范围主要包括：
  - `saga/runtime_diagnostics.py`
  - `saga/agent.py`
  - `experiments/result_logging.py`
  - `experiments/schedule_meeting.py`
  - `tests/test_runtime_diagnostics.py`
  - `tests/test_schedule_meeting.py`
  - `tests/test_result_logging.py`
  - `SAGA_PQ_CAN_WORKLOG.md`
- 当前工作区同时包含敏感/生成物，因此本次只保留 commit-ready checkpoint 摘要，不自动推送备份分支。

### 2026-05-15 Preflight Guardrail Session

目标：

- 将“普通 rerun 不改信任链”的约束落实为仓库内只读脚本和文档规则。
- 在真实实验前提前发现 `CA / Provider / user / agent / DB` 之间的状态漂移。

已做工作：

- 新增只读脚本：
  - `experiments/preflight.py`
- 当前 preflight 默认执行以下检查：
  - `.ca_static/` 与 `saga/ca/` 是否分离且公钥材料一致
  - `saga/provider/provider.crt` 是否由当前 CA 签发
  - 给定 `user_config` 对应的本地 user / agent 证书是否由当前 CA 签发
  - 本地 Provider 数据库中的 `users / agents` 注册证书是否与本地文件一致
- 新增 `--repair-plan` 模式：
  - 只输出修复建议
  - 不会自动执行任何状态修改
- 兼容了两类本地 agent 证书形态：
  - 独立 `agent.crt`
  - 仅存在于 `agent.json.agent_cert` 的嵌入式证书
- 更新文档：
  - `README.md` 增加真实实验前的 preflight 用法
  - 本工作文档增加 preflight 状态、任务项和当前下一步要求
- 新增测试：
  - `tests/test_preflight.py`
  - 覆盖：
    - 正常通过
    - DB 证书失配提前失败
    - `.ca_static/` 与 `saga/ca/` 公钥漂移
    - `agent.json` 内嵌证书回退路径
- 在当前 `emma / raj` 真实环境上实际执行：
  - `.venv/bin/python experiments/preflight.py --user-config user_configs/emma.yaml --user-config user_configs/raj.yaml`
  - 实测结果为 `Overall: PASS`

测试结果：

- `.venv/bin/python -m pytest -q` -> `121 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `12 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/test_preflight.py tests/test_result_logging.py tests/test_schedule_meeting.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `14 passed, 12 subtests passed`

当前结论：

- 以后普通真实 rerun 前已经有一条只读前置护栏，不需要再依赖临场记忆判断是否能直接开跑。
- 当前 `preflight` 已能在真实 `emma / raj` 本地环境上通过，并且能覆盖这次暴露过的核心漂移风险：
  - 当前 CA 与旧 Provider 证书不一致
  - 当前 CA 与旧 user / agent 证书不一致
  - 本地证书与 Provider DB 注册状态不一致

阻塞 / 注意事项：

- 当前工作区仍包含不应自动推送的敏感/生成物：
  - `saga/provider/provider.*.selfsigned`
  - `saga/provider/provider.*.bad-20260515`
  - `experiments/results/`
  - `.tmp_reregister_20260515/`
  - `.tmp_rerun_20260515/`
- 因命中上述路径，本次不应自动推送备份分支。

GitHub / checkpoint 状态：

- 已执行 `git status --short` 检查。
- 当前新增的安全代码范围主要包括：
  - `experiments/preflight.py`
  - `tests/test_preflight.py`
  - `README.md`
  - `SAGA_PQ_CAN_WORKLOG.md`
- 当前工作区同时还混有敏感/生成物与此前未整理改动，因此本次只保留本地 checkpoint 摘要，不自动推送备份分支。

## 9. 目标调整记录

### 2026-04-30

原始意图：

- 直接评估“是否应该立刻把原验签模块改成 LWE + CNN/DNN 认证神经元”

调整后的执行策略：

- 先不直接替换全部验签逻辑
- 先建立 SAGA 基线与最小测试基线
- 后续以 middleware 增量接入 PQ-CAN，而不是先大改现有 identity / TLS / OTK 逻辑
- 每次会话结束前增加 GitHub checkpoint，同步当前项目状态并把结果写入工作日志

调整原因：

- 设计文档要求保留 SAGA 语义
- 当前仓库还缺自动化测试与 PQ-CAN 代码骨架
- 先补基线可以降低后续接入风险与返工成本
- 用户要求每次结束前同步 GitHub，以保证跨会话衔接与远端备份

### 2026-05-07

原始表述：

- 将 PQ-CAN 的主接入点表述为 receiving agent middleware
- 将最终判定表述为 `allow = saga_token_valid AND can_accept`

调整后的执行策略：

- 保持 `SAGA` 只负责协议层准入，不让 PQ-CAN 替代 `identity / registry / contact policy / OTK / token / TLS`
- 将 `PQ-CAN` 明确定位为执行层准入控制，而不是只在网络入口做一次验签
- 将最终约束显式拆分为：
  - `protocol_allow = saga_token_valid`
  - `execution_allow = can_accept`
  - `allow = protocol_allow AND execution_allow`
- 将执行层 gate 至少接入以下节点：
  - 消息进入 `LLM prompt`
  - 消息进入 `memory`
  - 消息触发 `tool executor`
  - 消息触发 `delegation chain`
- 将 CAN 的验证目标明确为四类硬约束：
  - 来源合法性
  - `SAGA` 上下文绑定
  - 执行面授权
  - 二进制输入合法性与实数绕过拒绝

调整原因：

- 单独的 `SAGA token` 只能保证通信层访问受控，不能单独约束消息进入 Agent 内部执行链后的影响面。
- 单点 middleware 验证过于粗糙，无法覆盖 `memory / tool / delegation` 这些高风险执行面。
- 当前最合理的研究原型边界，是让 CAN 做确定性硬认证门，而不是做自然语言语义分类器。

### 2026-05-09

原始表述：

- 将 `LWE-CNN` 与 `LWE-DNN` 并列为当前可直接展开的实现方向

调整后的执行策略：

- 当前先不直接追 `CNN + Ring/Module-LWE`
- 先用当前 `toy/general-matrix LWE` 实现 `compiled DNN verifier`
- 先验证以下核心命题：
  - 合法二进制输入可通过
  - 非法签名可拒绝
  - real-valued / boundary 输入可由 `STEP/RECT/MASK` 拒绝
- 在架构可行性得到验证后，再升级到：
  - `CNN + Ring/Module-LWE`
  - 作为结构匹配、潜在效率优化与论文亮点增强方向

调整原因：

- 当前仓库里的 `toy_lwe` 是一般矩阵结构，更自然对应固定 `Linear/DNN` 编译，而不天然对应 CNN。
- 直接追 CNN 会把“验证架构可行性”和“引入更复杂格结构”两件事耦合在一起，放大实现风险。
- 先完成 compiled DNN verifier，可以最大化复用现有 `CAN / execution_gate / request_envelope / tests` 基础设施，再为后续 CNN 升级提供稳定基线。

### 2026-05-16

当前工作焦点：

- 按“当前 baseline 的真实阻塞点已经收缩到 CodeAgent Step 1 首轮模型调用/agent 规划”的判断继续排障。
- 本轮没有直接重跑真实 `schedule_meeting` baseline，因为当前 shell 中未运行 `MongoDB / CA / Provider / schedule_meeting listen` 进程。
- 已确认 `OPENAI_API_KEY` 在当前 shell 中存在，但未打印密钥值。

本轮定位结论：

- 旧诊断只在 `local_agent.run()` 返回之后写入，因此如果 receiver-side `CodeAgent` 卡在首轮模型调用或抛出异常后连接被关闭，`diagnostics/local_agent_runs.jsonl` 可能完全没有记录。
- 这会造成“agent 已进入 Step 1，但运行后没有返回结果”的排障盲区：无法区分模型调用未返回、模型调用异常、还是工具/业务 oracle 失败。

本轮修复：

- `saga/agent.py`
  - 新增 `_run_local_agent_with_diagnostics(...)`，在 `local_agent.run()` 前写入 `run_status=started`，成功后写入 `run_status=completed`，异常后写入 `run_status=failed` 与异常摘要。
  - receiver / initiator 两侧均改为通过该 helper 调用 `local_agent.run()`。
  - 给 agent socket 设置 `CONVERSATION_SOCKET_TIMEOUT_SECONDS = 120.0`，避免对端模型调用长时间不返回时另一侧永久阻塞在 `recv()`。
  - overhead 日志改用 `_llm_elapsed_seconds(...)`，避免未发生 LLM run 时诊断代码自身再次抛错。
- `tests/integration/test_baseline_agent_flow.py`
  - 新增本地 agent 异常路径测试，验证 receiver-side 会写入 `started -> failed` 诊断记录，而不是静默消失。

验证结果：

- `.venv/bin/python -m pytest -q` -> `122 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此本轮未运行对应命令。

下一次真实 rerun 的判断方式：

- 如果 receiver workdir 的 `diagnostics/local_agent_runs.jsonl` 只有 `run_status=started`，没有 `completed/failed`，则真实阻塞点就是 `CodeAgent.run()` 内部的首轮模型调用/agent 规划未返回。
- 如果出现 `run_status=failed`，优先看 `error` 字段；此前真实栈最相关的候选仍是 OpenAI timeout / API 调用异常。
- 如果出现 `run_status=completed`，再看 `tool_call_names`、`error_step_count`、`final_answer_step_count` 与 `ScheduleMeetingOracle`，判断是否进入工具调用或业务 oracle 失败。

追加真实 rerun 结果：

- 本轮实际启动了 repo-local `MongoDB / CA file server / Provider / Raj calendar_agent listener`。
- 初始 preflight 失败：
  - Provider DB 中 Emma 注册材料与本地文件不一致；
  - Raj 注册缺失；
  - 两个 calendar_agent 目录残留旧 `agent.crt`，而 `register_agent()` 只更新 `agent.json`，导致 preflight 优先读取旧证书。
- 已按 preflight repair-plan 做本地测试环境修复：
  - 删除 Provider DB 中 Emma/Raj 相关旧注册行；
  - 重新执行 baseline `register + register-agents`；
  - 将两个旧 calendar_agent `agent.crt` 重命名为 `.stale-20260516`，让 preflight 回退读取最新 `agent.json`；
  - 重新 seed 工具数据。
- 修复后 preflight 通过。
- 真实 `schedule_meeting` baseline rerun 结果：
  - `/access` 成功；
  - TLS 建连成功；
  - token 发放成功；
  - receiver 进入 `CodeAgent Step 1`；
  - receiver workdir 诊断写入 `run_status=started`；
  - 120 秒后 initiator socket read timeout，实验结果 `success=false`；
  - receiver 诊断没有出现 `completed` 或 `failed`。
- 最小 OpenAI SDK 探针返回：
  - `openai.RateLimitError: 429 insufficient_quota`
- `smolagents` 当前重试参数：
  - `RETRY_MAX_ATTEMPTS=3`
  - `RETRY_WAIT=60`
  - `RETRY_EXPONENTIAL_BASE=2`
  - `RETRY_JITTER=True`

当前结论：

- 当前真实 baseline 未跑通的直接原因不是 SAGA token / TLS / Provider / PQ-CAN gate。
- 当前阻塞点已进一步收缩为：OpenAI 账户 quota 不足触发 429，`smolagents` 将 429 作为可重试错误退避，导致 receiver-side `CodeAgent Step 1` 长时间无返回。
- 下一步应优先处理模型后端：
  - 换可用 OpenAI key / project；
  - 或临时改用本地/可用测试模型；
  - 或在 `OpenAIServerModel` 初始化中禁用 retry / 对 `insufficient_quota` fail-fast，以便实验快速失败并写入 `run_status=failed`。

追加配置修复：

- 已将所有 `user_configs/*.yaml` 中的 `api_base` 统一改为 `https://oai.codexi.eu.cc/v1`。
- `agent_backend/config.py` 新增 `DEFAULT_OPENAI_API_BASE`，未来未特殊覆盖的 `LocalAgentConfig` 默认使用该 endpoint。
- `agent_backend/base.py` 已更新 API key 选择逻辑，使默认 Codexi OpenAI-compatible endpoint 与官方 OpenAI endpoint 一样读取 `OPENAI_API_KEY`。
- `README.md` 中 PQ-CAN 配置示例同步改为新的默认 endpoint。
- 新增 `tests/test_agent_backend_config.py`，覆盖默认 endpoint、key 读取判断，以及所有 checked-in `user_configs` 示例的 `api_base`。

验证结果：

- `.venv/bin/python -m pytest -q` -> `125 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此本轮未运行对应命令。

### 2026-05-16 Model Backend Preflight Session

目标：

- 根据工作焦点继续处理真实 baseline 的模型后端阻塞。
- 避免再次启动完整 `schedule_meeting` baseline 后才在 `CodeAgent Step 1` 等到 socket timeout。

已做工作：

- 不打印密钥；仅在本地确认当前 shell 的 `OPENAI_API_KEY` 已设置，未将 masked 值或哈希指纹写入仓库。
- 先跑最小 SDK 探针：
  - sandbox 内 DNS 失败；
  - 网络提权后可连通 endpoint，但返回 `openai.InternalServerError: 503 Service temporarily unavailable`。
- 将模型后端可用性检查接入 `experiments/preflight.py`：
  - 新增 opt-in `--model-probe`
  - 新增 `--model-probe-timeout`
  - 默认 preflight 仍只做信任链 / DB 检查，不联网、不消耗模型 quota。
  - `--model-probe` 会对配置中的唯一 `OpenAIServerModel` endpoint 发送 tiny chat-completions 请求，并用 `max_retries=0` fail fast。
- 将 `api_base_requires_openai_api_key(...)` 下沉到 `agent_backend/config.py`，避免 preflight 为了判断 key 需求导入完整 smolagents agent 栈。
- 将 `openai` 写入 `requirements.txt` 与 `setup.py`，避免新环境只在 `.venv` 中手工补装后才能运行真实 OpenAI-compatible 路径。
- 更新 `README.md`，说明真实 LLM-backed experiment 前可运行 opt-in model probe。
- 新增 / 更新测试：
  - `tests/test_preflight.py`
  - `tests/test_agent_backend_config.py`

实测结果：

- `.venv/bin/python experiments/preflight.py --user-config user_configs/emma.yaml --user-config user_configs/raj.yaml --skip-db-sync --model-probe --model-probe-timeout 5 --json`
  - sandbox 内：信任链通过；模型 probe 因 DNS 连接失败而失败。
  - 网络提权后：
    - 信任链检查全部通过；
    - `gpt-4.1-mini-2025-04-14@https://oai.codexi.eu.cc/v1` -> `openai.APITimeoutError: Request timed out.`
    - `gpt-4.1-2025-04-14@https://oai.codexi.eu.cc/v1` -> `openai.InternalServerError: 503 Service temporarily unavailable`

当前结论：

- 当前新 key 已被本会话继承，旧的 `401 INVALID_API_KEY` 状态不再是当前观测结果。
- 当前仍不能启动完整真实 baseline；阻塞转为 Codexi/OpenAI-compatible endpoint 当前 timeout / 503。
- 下一次应先跑 `--model-probe`，只有模型 probe 通过后才启动 `MongoDB / CA / Provider / Raj listener / Emma query`。

追加 `gpt-5.2` rerun 结果：

- 用户决定不再使用 4.1，并要求改用 5.2，同时去掉 dated snapshot 名称。
- 已将 checked-in `OpenAIServerModel` 示例配置改为非 dated alias `gpt-5.2`：
  - `user_configs/emma.yaml`
  - `user_configs/raj.yaml`
  - `user_configs/emma_pqcan.yaml`
  - `user_configs/raj_pqcan.yaml`
  - `README.md`
  - 相关测试示例
- 已实测：
  - 直接 OpenAI SDK `gpt-5.2` 探针 -> `OK ok`
  - `experiments/preflight.py --model-probe` -> `ok=true`
  - smolagents `OpenAIServerModel(model_id="gpt-5.2", temperature=0.0)` -> `OK ok`
- 当前模型后端阻塞已解除；下一步可启动真实 `schedule_meeting` baseline rerun。

追加真实 baseline 启动结果：

- 已启动并关闭本轮本地服务：
  - repo-local `MongoDB`
  - `.ca_static` CA file server
  - Provider
  - Raj `calendar_agent` listener
- 启动前 preflight 全部通过：
  - CA / Provider / user / agent cert
  - Provider DB 注册状态
  - `model_probe:OpenAIServerModel:gpt-5.2@https://oai.codexi.eu.cc/v1`
- 执行：
  - `.venv/bin/python experiments/schedule_meeting.py listen user_configs/raj.yaml`
  - `.venv/bin/python experiments/schedule_meeting.py query user_configs/emma.yaml user_configs/raj.yaml`
- 结果：
  - `Success: True`
  - `oracle_success: true`
  - `oracle_reason: meeting_scheduled`
  - matched event: `2026-05-19T09:00:00` -> `2026-05-19T09:30:00`
  - `local_run_count: 4`
  - `local_run_tool_call_count: 4`
  - `local_run_error_step_count: 0`
  - `peer_run_count: 7`
  - `peer_run_tool_call_count: 4`
  - `peer_run_error_step_count: 0`
  - `peer_audit_reject_count: 0`
- 结果已追加到 `experiments/results/schedule_meeting.jsonl`。
- 本轮启动的长驻进程均已关闭；最新进程检查未发现遗留 `mongod / http.server / provider.py / schedule_meeting.py`。

验证结果：

- `.venv/bin/python -m pytest -q tests/test_preflight.py tests/test_agent_backend_config.py` -> `11 passed, 8 subtests passed`
- `.venv/bin/python -m pytest -q` -> `129 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此本轮未运行对应命令。

GitHub / checkpoint 状态：

- 已执行 `git status --short --branch`。
- 已执行 `git diff --check`，无 whitespace error。
- 已整理工作区并通过 `.gitignore` 排除本地生成物、实验结果、agent 诊断、临时注册目录和证书/私钥备份。
- 已形成本地 checkpoint：
  - `fb62e90 checkpoint: preflight and runtime diagnostics`
- 已推送到远程备份分支：
  - `origin/backup/repro-local`
- 当前 `repro-local` 相对 `origin/repro-local` 仍是本地研究分支 ahead 状态；不要直接 push 到主开发分支。
- 最新善后检查：
  - 当前未发现遗留 `mongod / http.server / provider.py / schedule_meeting.py / create_blogpost.py` 进程。
  - 生成/敏感材料仍仅保留在本地并被忽略：实验结果、诊断 JSONL、临时注册材料、证书/私钥备份。

下一次接续建议：

1. 从 `fb62e90` 或 `origin/backup/repro-local` 继续。
2. 先运行只读 preflight；真实 LLM-backed 实验前再按需运行 opt-in `--model-probe`。
3. 进入正式 `Batch 1` 前，先清理或归档旧实验结果 JSONL，避免把排障样本混入正式统计。
4. 按 `test_optimized.md` 顺序执行：baseline 三任务 -> PQ-CAN 正向三任务 -> 两个最小负向场景。
5. 每个真实任务结束后检查 receiver 侧 audit 与 runtime diagnostics，确认失败原因能归类到模型、连接、工具、oracle 或 execution gate。

### 2026-05-18 Batch 1 Attempt

目标：

- 根据工作文档继续进入正式 `Batch 1` 前置与 baseline rerun。
- 清理旧实验结果，避免正式统计混入排障样本。

已做工作：

- 归档旧 `experiments/results/*.jsonl` 到 ignored archive 目录。
- 启动并关闭本轮本地服务：
  - repo-local `MongoDB`
  - `.ca_static` CA file server
  - Provider
  - Raj `calendar_agent` listener
- 运行 preflight：
  - 本地 DB / CA / Provider / user / agent cert 同步检查通过。
  - 初始 5 秒模型 probe 曾出现 `APIConnectionError`。
  - 20 秒模型 probe 随后通过一次。
- 重新 seed 工具数据，启动 baseline `schedule_meeting` rerun。
- 第一轮 baseline rerun：
  - SAGA `/access`、TLS、token 发放、receiver-side `CodeAgent` 均通过。
  - 业务 oracle 失败，原因是发起侧模型把邀请邮箱生成为 `alex.chen@acme.com`，导致 Emma 日历没有匹配事件。
  - 该样本已归档到 `experiments/results/archive/20260518T075600Z-meeting-prompt-unbound/`。
- 修复 `experiments/schedule_meeting.py`：
  - 新增 `build_schedule_meeting_task(...)`，在真实 prompt 中显式绑定发起人姓名、真实邮箱和 receiver 名称。
  - 要求 calendar event 使用 `emma_johnson@gmail.com`，禁止 placeholder / example email。
  - 补 `tests/test_schedule_meeting.py` 覆盖 prompt 绑定。
- 第二轮 baseline rerun：
  - prompt 已按预期绑定 `emma_johnson@gmail.com`。
  - receiver 侧完成第一轮响应，但 initiating-side `CodeAgent` 生成失败：
    - `smolagents.utils.AgentGenerationError: Error in generating model output: Connection error.`
  - 随后 opt-in `--model-probe --model-probe-timeout 20` 失败：
    - `openai.APITimeoutError: Request timed out.`
  - 该样本已归档到 `experiments/results/archive/20260518T080400Z-model-timeout/`。
- 修复 runtime diagnostics 统计污染：
  - `saga/runtime_diagnostics.py`
    - 新增 `filter_diagnostics_since(...)`，按本次运行开始时间过滤诊断记录。
    - `summarize_local_run_diagnostics(...)` 新增 `*_by_status`、`*_failed_count`、`*_errors`。
  - `experiments/schedule_meeting.py`
    - query 结果只汇总本次运行窗口内的 local / peer diagnostics，不再把历史 workdir 诊断累加进当前结果。
  - `tests/test_runtime_diagnostics.py`
    - 覆盖 run window 过滤和 failed status/error 汇总。

验证结果：

- `.venv/bin/python -m pytest -q tests/test_runtime_diagnostics.py tests/test_schedule_meeting.py tests/test_result_logging.py` -> `11 passed`
- `.venv/bin/python -m pytest -q` -> `131 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此本轮未运行对应命令。
- `git diff --check` 无 whitespace error。

当前结论：

- 当前真实 Batch 1 还不能继续往下计数，但最新阻塞点已经不是模型 endpoint timeout，而是 `schedule_meeting` 的业务 oracle 不通过。
- 最新 clean rerun 的 `query` 结果是 `success=false`，`oracle_reason=no_matching_event_found`。
- 从结果看，SAGA `/access`、TLS、token 发放、receiver-side `CodeAgent` 和双方对话都已经走通，失败发生在最后的日历验收阶段。
- 具体表现是 `self_upcoming_event_count=0`、`peer_upcoming_event_count=1`：Raj 侧日历里出现了 1 条未来会议，但 Emma 侧没有对应事件。换句话说，会议没有同时写进双方日历，或者两边事件的时间、标题、details 没有完全一致，导致 oracle 找不到“同一条会议”。
- 所以前一次 rerun 的 `Connection error / APITimeoutError` 是另一类排障样本，和这次最新 clean rerun 不是同一个阻塞点。
- `schedule_meeting` prompt 已更适合正式计数，不应再允许模型编造外部邮箱。
- 当前 diagnostics 汇总已改为本次运行窗口，后续结果文件不会再被历史 workdir 诊断污染。
- `experiments/results/` 当前正式 JSONL 已归档清空；旧样本均在 ignored archive 下。

GitHub / checkpoint 状态：

- 已执行 `git status --short --branch`。
- 本轮待提交 tracked 文件范围：
  - `SAGA_PQ_CAN_WORKLOG.md`
  - `experiments/schedule_meeting.py`
  - `saga/runtime_diagnostics.py`
  - `tests/test_runtime_diagnostics.py`
  - `tests/test_schedule_meeting.py`
- 本轮启动的长驻进程均已关闭；最新检查未发现遗留 `mongod / http.server / provider.py / schedule_meeting.py / expense_report.py / create_blogpost.py`。
- 本轮收尾阶段准备形成本地 checkpoint commit；提交哈希以 `git log` / 本次最终回复为准。
- 满足安全条件时推送到 `origin/backup/repro-local`，不要推主开发分支。

下一次接续建议：

1. 先运行：
   - `.venv/bin/python experiments/preflight.py --user-config user_configs/emma.yaml --user-config user_configs/raj.yaml --skip-db-sync --model-probe --model-probe-timeout 20 --json`
2. 只有模型 probe 通过后，才重新启动 `MongoDB / CA / Provider / listener / query`。
3. 继续正式 `Batch 1` baseline 三任务；不要把本轮归档排障样本计入正式统计。
4. 每个任务结果看 query 行，并检查本次窗口内 diagnostics 的 `*_by_status` / `*_failed_count` / `*_errors`。

### 2026-05-18 Single-Entry Batch Runner

目标：

- 接续上次中断的“单入口批跑脚本”任务。
- 将“连续 model probe 稳定后再启动本地服务、seed 数据、执行正式任务”的手工流程脚本化。

已做工作：

- 新增 `experiments/batch_run.py`：
  - 默认选中 `schedule_meeting`，也支持 `--task all` 顺序运行三项正向任务。
  - 默认连续 2 次 model probe 全部通过后才继续。
  - model probe 阶段会同时跑文件侧信任链检查；非模型类 preflight 失败会 fail-fast，不会被当作模型波动重试。
  - 自动启动本地 `mongod`、`.ca_static` HTTP file server、Provider；如果这些基础服务端口已经开启，会复用已有服务。
  - 自动调用 `seed_tool_data`，再按每个任务的 receiver agent 端口启动 `listen`，随后执行 `query`。
  - 在启动 listener 前检查 receiver 端口不能已被占用，避免误连旧 listener。
  - 只接受本次 query 后新增的 `mode=query` 结果行，避免历史成功记录掩盖当前失败。
  - 退出时关闭本脚本启动的服务与 listener。
  - 运行日志、manifest、model probe JSON、trust-chain preflight JSON 写入 `experiments/runs/`。
- 更新 `.gitignore`：
  - 忽略 `experiments/runs/`。
- 更新 `README.md`：
  - 增加 `experiments/batch_run.py` 用法。
- 更新 `test_optimized.md`：
  - 将“统一批跑脚本不可执行”的旧结论改为“正向任务第一版批跑入口已可用”。
  - 保留负向自动注入批跑仍未完成的限制。
- 新增 `tests/test_batch_run.py`：
  - 覆盖 `--task all` 展开顺序。
  - 覆盖本地服务和实验入口命令构造。
  - 覆盖连续 model probe 稳定条件。
  - 覆盖非模型 preflight 失败 fail-fast。
  - 覆盖当前 query 结果不能被旧结果替代。
  - 覆盖 stale listener 端口占用时拒绝启动任务。

验证结果：

- `.venv/bin/python -m pytest -q tests/test_batch_run.py` -> `7 passed`
- `.venv/bin/python -m py_compile experiments/batch_run.py` -> 通过
- `.venv/bin/python experiments/batch_run.py --help` -> 通过
- `.venv/bin/python -m experiments.batch_run --help` -> 通过
- `.venv/bin/python -m pytest -q` -> `138 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- `git diff --check` -> 通过
- 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。

当前结论：

- 单入口正向批跑入口已经可用；下一次真实 rerun 可直接触发一次脚本，而不是手工轮询 model probe 与逐步启动服务。
- 本轮未运行真实 LLM-backed 批跑，因为该脚本默认会联网并消耗 API quota；本次只完成实现与自动化单元/集成测试验证。
- 负向场景自动注入仍未实现；当前 `batch_run.py` 仅覆盖正向任务 listen/query 编排。

GitHub / checkpoint 状态：

- 待提交 tracked 文件范围：
  - `.gitignore`
  - `README.md`
  - `SAGA_PQ_CAN_WORKLOG.md`
  - `test_optimized.md`
  - `experiments/batch_run.py`
  - `tests/test_batch_run.py`
- 本轮没有生成需要提交的 secrets、凭据、本地数据库、模型输出或 `paper/` 改动。
  - `experiments/runs/` 已被 `.gitignore` 忽略。
- 收尾时应执行 `git status --short --branch` 并准备本地 checkpoint；若安全条件满足，可推送到 `origin/backup/repro-local`。

### 2026-05-18 Code Comment / Docstring Pass

目标：

- 根据仓库注释规则，为现有必要代码补充中文 docstring 和关键边界注释。
- 仅补充说明，不改变运行逻辑或安全决策。

已做工作：

- 为源码目录中的公开类/函数补齐中文说明，覆盖：
  - `agent_backend/` 本地 agent 包装与工具类。
  - `experiments/` 实验入口和结果检查类。
  - `saga/` 运行时、provider/CA、contact policy、logger、旧安全回归场景。
  - `generate_credentials.py` 凭据生成入口。
- 在核心安全路径补充必要中文注释：
  - CAN 在 MASK 二值检查通过后才调用签名 verifier。
  - compiled toy LWE verifier 只使用公开矩阵、签名向量和消息挑战恢复公钥。
  - signed execution gate 先验证信封时间窗，再执行神经验签；失败默认拒绝。
  - 请求信封要求 timezone-aware 时间，避免本地时区解释有效期。
  - outbound runtime auth 只把 token/message 哈希写入签名信封。
- 对 `saga/attack_models/` 的旧 adversary 文件只补“防御回归场景/应被拒绝行为”说明，没有添加攻击性利用逻辑。
- 使用 AST 扫描确认 `agent_backend/`、`experiments/`、`neural/`、`pq/`、`saga/` 和 `generate_credentials.py` 中公开类/函数无 docstring 缺口；剩余缺口仅在测试里的局部假对象/helper，未作为公开 API 处理。

验证结果：

- `python3 -m compileall -q agent_backend experiments generate_credentials.py neural pq saga` -> 通过
- `.venv/bin/python -m pytest -q` -> `138 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- `git diff --check` -> 通过
- 仓库未发现 `pyproject.toml`、`setup.cfg`、`ruff.toml`、`.ruff.toml` 或 `mypy.ini`，因此未运行 `ruff check .` / `mypy .`。

当前待提交文件范围：

- `agent_backend/base.py`
- `agent_backend/tools/base.py`
- `agent_backend/tools/calendar.py`
- `agent_backend/tools/documents.py`
- `agent_backend/tools/email.py`
- `experiments/adversary.py`
- `experiments/create_blogpost.py`
- `experiments/expense_report.py`
- `experiments/hello_world.py`
- `experiments/schedule_meeting.py`
- `experiments/seed_tool_data.py`
- `experiments/test.py`
- `generate_credentials.py`
- `neural/can.py`
- `neural/compiled_lwe_dnn.py`
- `saga/agent.py`
- `saga/attack_models/adversaries/A1.py`
- `saga/attack_models/adversaries/A2.py`
- `saga/attack_models/adversaries/A3.py`
- `saga/attack_models/adversaries/A4.py`
- `saga/attack_models/adversaries/A5.py`
- `saga/attack_models/adversaries/A6.py`
- `saga/attack_models/adversaries/A8.py`
- `saga/attack_models/benign/A5.py`
- `saga/ca/CA.py`
- `saga/common/contact_policy.py`
- `saga/common/logger.py`
- `saga/execution_gate.py`
- `saga/local_agent.py`
- `saga/messages.py`
- `saga/provider/provider.py`
- `SAGA_PQ_CAN_WORKLOG.md`

当前结论：

- 本轮是注释/docstring checkpoint，没有新增模块、密钥、凭据、本地数据库、模型输出或 `paper/` 改动。
- 代码语法、完整测试、安全测试和集成测试均通过。

### 2026-05-19 Batch 1 Baseline Formal Run

目标：

- 按工作文档启动正式 `Batch 1` baseline 三任务重新计数。
- 只使用 baseline 配置：
  - `user_configs/emma.yaml`
  - `user_configs/raj.yaml`

已做工作：

- 归档旧 `experiments/results/schedule_meeting.jsonl`，确保正式结果目录不混入历史排障样本。
- 首次从受限网络沙箱启动批跑时，model probe 持续失败：
  - `openai.APIConnectionError: Connection error.`
  - 该轮未进入 listener/query，不计入正式 Batch。
- 使用外部网络权限重新运行：
  - `.venv/bin/python experiments/batch_run.py --task all --initiator-config user_configs/emma.yaml --receiver-config user_configs/raj.yaml`
- 第一轮真实任务进入 `schedule_meeting` 后失败：
  - `oracle_reason = no_matching_event_found`
  - 模型选择 `2026-05-19 09:00-09:30`，但运行时已经是当天傍晚，`get_upcoming_events()` 与 oracle 把该事件视为过去事件排除。
  - 该样本已归档到 ignored archive：
    - `experiments/results/archive/20260519T093149Z-meeting-past-slot/`
- 修复 `experiments/schedule_meeting.py`：
  - 新增 `_next_workday_anchor(...)`，把 live prompt 锚定到未来工作日 09:00。
  - `build_schedule_meeting_task(...)` 现在写入绝对目标日期与 09:00-17:00 时间窗，不再让模型从模糊的 “Tuesday” 推断日期。
- 更新 `tests/test_schedule_meeting.py`：
  - 覆盖 prompt 中的绝对日期 / 时间窗。
  - 覆盖傍晚运行与周五傍晚运行时锚点跳到未来工作日。
- 重新运行正式 baseline 三任务并通过：
  - 运行目录：`experiments/runs/20260519T094007Z-schedule_meeting-expense_report-create_blogpost/`
  - `schedule_meeting` query：`success=true`
  - `expense_report` query：`success=true`
  - `create_blogpost` query：`success=true`

正式 baseline 结果摘要：

- `schedule_meeting`：
  - `oracle_reason = meeting_scheduled`
  - `matched_event_time_from = 2026-05-20T09:00:00`
  - `matched_event_time_to = 2026-05-20T09:30:00`
  - `peer_audit_reject_count = 0`
- `expense_report`：
  - `success = true`
  - `runtime_auth_enabled = false`
- `create_blogpost`：
  - `success = true`
  - `runtime_auth_enabled = false`
- 三项均为 baseline 配置，未启用 PQ-CAN runtime auth。

验证结果：

- `.venv/bin/python -m pytest -q tests/test_schedule_meeting.py tests/test_calendar_tool.py tests/test_batch_run.py` -> `12 passed`
- `.venv/bin/python -m pytest -q tests/test_schedule_meeting.py` -> `4 passed`
- `.venv/bin/python -m pytest -q` -> `142 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `13 passed, 12 subtests passed`
- `git diff --check` -> 通过
- 仓库未发现 `pyproject.toml`、`setup.cfg`、`ruff.toml`、`.ruff.toml` 或 `mypy.ini`，因此未运行 `ruff check .` / `mypy .`。

当前结论：

- `H5. 正式 Batch 1 baseline 三任务重新计数` 已完成。
- 当前阻塞不在 SAGA `/access`、TLS、token、receiver-side `CodeAgent` 或 baseline task oracle。
- 下一步应进入 `PQ-CAN` 正向三任务真实验证：
  - `.venv/bin/python experiments/batch_run.py --task all --initiator-config user_configs/emma_pqcan.yaml --receiver-config user_configs/raj_pqcan.yaml`
- 本轮真实测试结束后未发现遗留 `mongod / http.server / provider.py / schedule_meeting.py / expense_report.py / create_blogpost.py / batch_run.py` 进程。

GitHub / checkpoint 状态：

- 待提交 tracked 文件范围：
  - `SAGA_PQ_CAN_WORKLOG.md`
  - `experiments/schedule_meeting.py`
  - `tests/test_schedule_meeting.py`
- 本轮真实结果、run 日志、历史失败样本均位于 ignored 路径：
  - `experiments/results/`
  - `experiments/runs/`
- 本轮没有需要提交的 secrets、生成凭据、本地数据库、模型输出或 `paper/` 改动。
- 收尾时应执行 `git status --short --branch` 并准备本地 checkpoint；若安全条件满足，可推送到 `origin/backup/repro-local`。

### 2026-05-19 PQ-CAN Positive Run Attempt / Tool-Scope Blocker

目标：

- 继续上一节的正式流程，启动 `PQ-CAN` 正向三任务真实验证：
  - `.venv/bin/python experiments/batch_run.py --task all --initiator-config user_configs/emma_pqcan.yaml --receiver-config user_configs/raj_pqcan.yaml`
- 验证 `emma_pqcan.yaml` -> `raj_pqcan.yaml` 的 runtime-auth 链路是否能穿过 model probe、trust-chain preflight 和真实任务。

本轮发生的情况：

- 受限网络沙箱内首次启动 PQ-CAN 批跑：
  - 运行目录：`experiments/runs/20260519T133604Z-schedule_meeting-expense_report-create_blogpost/`
  - 结果：反复停在 model probe；`model_probe_001.json` 到后续 probe 均显示：
    - `openai.APIConnectionError: Connection error.`
  - CA / Provider / user cert / agent cert 检查均为 `ok=true`。
  - 该轮没有进入 listener/query，不计入正式 PQ-CAN 结果。
- 使用外部网络权限重跑同一命令：
  - 运行目录：`experiments/runs/20260519T134139Z-schedule_meeting-expense_report-create_blogpost/`
  - `model probe passed (2/2)`
  - `trust_chain_preflight passed`
  - tool seed 已执行
  - 已进入 `schedule_meeting` listen/query
  - 批跑在第一项任务后停止，原因是 `schedule_meeting query did not succeed; latest result success=False`
  - 因第一项失败，`expense_report` 与 `create_blogpost` 未继续执行。

`schedule_meeting` PQ-CAN 失败摘要：

- 最新 query record：
  - `runtime_auth_enabled = true`
  - `success = false`
  - `oracle_reason = no_matching_event_found`
  - `self_upcoming_event_count = 0`
  - `peer_upcoming_event_count = 0`
  - `peer_audit_reject_count = 0`
- receiver 侧真实日志显示：
  - receiver 已通过外层 SAGA access/token/TLS 流程。
  - PQ-CAN ingress gate 没有拒绝整条消息；没有出现 receiver-side execution-gate audit reject。
  - 进入 `CodeAgent` 后，模型尝试调用：
    - `get_free_time_slots(time_from="2026-05-20 09:00:00", time_to="2026-05-20 17:00:00")`
  - 本地工具包装层拒绝执行：
    - `PermissionError: execution gate rejected tool call: get_free_time_slots`
  - 模型随后退化为“日历工具不可用”的对话，最终没有创建 calendar event，所以 oracle 判定 `no_matching_event_found`。

当前根因判断：

- 这不是模型后端、TLS、Provider DB、token、证书或 toy LWE 签名验签失败。
- 当前阻塞是 runtime-auth 的 action-scope 语义不匹配：
  - `saga/agent.py` 当前会话 payload 使用并签名 `action_scope="llm_prompt"`。
  - `agent_backend/base.py` 的工具包装层在真实工具执行前检查 `tool_call:<tool_name>`。
  - `saga/messages.py` 的 scope 语义是同 base 才能授权；`llm_prompt` 不授权 `tool_call:get_free_time_slots`。
  - 因此 receiver 外层消息验签通过，但下游工具调用按设计 fail-closed。
- 这说明 PQ-CAN 已经接入到真实 tool executor，但第一版正向任务还缺“签名请求如何授权工具调用”的策略。

下次续接建议：

1. 先不要重跑完整三任务；先修复或明确 action-scope 设计。
2. 需要在以下方案中选一个最小可审查路径：
   - 方案 A：让正向任务的 signed payload 使用宽 scope `tool_call`，从而授权本轮本地工具调用；需要评估这是否会弱化 `llm_prompt` 的显式绑定。
   - 方案 B：扩展 signed envelope，支持一个明确的 authorized scope/capability 列表，例如同时绑定 `llm_prompt` 与 `tool_call` 或具体 tool names。
   - 方案 C：把工具调用拆成单独签名的 tool-call envelope；更干净但改动更大。
3. 不建议简单把 `llm_prompt` 当作所有 tool call 的父权限；这会削弱当前 tool-level gate 的安全语义。
4. 修复前应补回归测试：
   - `llm_prompt` 不应授权 `tool_call:get_free_time_slots`。
   - 被明确授权的 `tool_call` 或 `tool_call:<tool_name>` 能通过真实 `AgentWrapper` tool gate。
   - `memory_write` / `delegation` 不应因为 tool 授权被顺带放开。
5. 修复后再运行：
   - `.venv/bin/python -m pytest -q`
   - `.venv/bin/python -m pytest -q tests/security`
   - `.venv/bin/python -m pytest -q tests/integration`
   - 外部网络权限下重新运行 PQ-CAN 正向三任务。

当前工作区状态：

- 已有未提交代码改动：
  - `experiments/schedule_meeting.py`
  - `tests/test_schedule_meeting.py`
- 本次 checkpoint 新增工作日志改动：
  - `SAGA_PQ_CAN_WORKLOG.md`
- 当前还存在一个未跟踪文件：
  - `.gitnore`
- 本轮 PQ-CAN 真实运行产物位于 ignored 路径：
  - `experiments/runs/20260519T133604Z-schedule_meeting-expense_report-create_blogpost/`
  - `experiments/runs/20260519T134139Z-schedule_meeting-expense_report-create_blogpost/`
  - `experiments/results/schedule_meeting.jsonl`
- 最新检查未发现实际遗留的 `mongod / http.server / provider.py / schedule_meeting.py / expense_report.py / create_blogpost.py / batch_run.py` 业务进程；批跑失败时已打印停止 `schedule_meeting_listen`、`provider`、`ca_http`、`mongod`。

收尾说明：

- 本轮按用户要求停止继续排障，只更新工作文档，方便下一次从 action-scope blocker 继续。
- 本轮未运行完整测试套件；最近一次完整通过仍是上一节 baseline checkpoint 记录的结果。

### 2026-05-20 PQ-CAN Positive Three-Task Pass / Assertion Repair

目标：

- 从上一轮 action-scope blocker 继续，先修复会话返回值断言，再运行相关测试。
- 若相关测试通过，继续执行 `PQ-CAN` 正向三任务真实验证。

本轮修复：

- 修正 `tests/integration/test_baseline_agent_flow.py` 中被前几次替换打乱的会话返回值断言：
  - 发起端收到对方 `<TASK_FINISHED>`：`initiate_conversation(...)` 返回 `False`
  - 接收端自己发出 `<TASK_FINISHED>` 完成：`receive_conversation(...)` 返回 `True`
  - 接收端收到发起方 `<TASK_FINISHED>`：`receive_conversation(...)` 返回 `False`
  - execution gate 拒绝本地执行：接收端本地结束并返回 `True`
- 保留并验证 explicit tool authorization scope 方案：
  - signed envelope 中可携带 `authorized_scopes`
  - `llm_prompt` 不默认授权 tool call
  - 显式签名的 `tool_call:<name>` 可传入 local execution context
  - structured local-agent response 会被稳定序列化后再签名传输

真实 `PQ-CAN` 正向三任务结果：

- 受限网络沙箱内首次运行仍停在 model probe：
  - 运行目录：`experiments/runs/20260520T114345Z-schedule_meeting-expense_report-create_blogpost/`
  - `model_probe_001.json` 与 `model_probe_002.json` 均为 `openai.APIConnectionError: Connection error.`
  - CA / Provider / user cert / agent cert 检查均为 `ok=true`
  - 未进入 listener/query，不计入正式结果
- 使用外部网络权限重跑后通过：
  - 命令：`.venv/bin/python experiments/batch_run.py --task all --initiator-config user_configs/emma_pqcan.yaml --receiver-config user_configs/raj_pqcan.yaml --probe-required-successes 1 --probe-max-attempts 2 --probe-interval 5 --model-probe-timeout 20 --query-timeout 1800`
  - 运行目录：`experiments/runs/20260520T114514Z-schedule_meeting-expense_report-create_blogpost/`
  - `model probe passed (1/1)`
  - `trust_chain_preflight passed`
  - `schedule_meeting`: `success=true`, `runtime_auth_enabled=true`, `peer_audit_reject_count=0`
  - `expense_report`: `success=true`, `runtime_auth_enabled=true`, `peer_audit_reject_count=0`
  - `create_blogpost`: `success=true`, `runtime_auth_enabled=true`, `peer_audit_reject_count=0`

本轮测试：

- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py` -> `11 passed`
- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_encoding.py tests/test_execution_gate.py tests/test_schedule_meeting.py tests/integration/test_baseline_agent_flow.py` -> `51 passed`
- `.venv/bin/python -m pytest -q` -> `152 passed, 20 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `15 passed, 12 subtests passed`
- 当前仓库没有发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前状态：

- `H6. 启动 PQ-CAN 正向三任务真实验证` 已完成。
- `H7. 启动两个最小负向场景真实验证` 已完成：
  - 缺失签名材料：`oracle_success=false`，`peer_audit_reject_count=1`，reason=`missing_request_envelope`
  - trusted public key 不匹配：`oracle_success=false`，`peer_audit_reject_count=2`，新增 reason=`signature_verification_failed`
- 最新检查未发现实际遗留的 `mongod / http.server / provider.py / schedule_meeting.py / expense_report.py / create_blogpost.py / batch_run.py` 业务进程；`pgrep` 只匹配到本次检查命令自身的 sandbox 包装进程。

### 2026-05-20 H7 Negative Scenario Pass

目标：

- 运行 `test_optimized.md` 中定义的两个最小负向场景：
  - 缺失签名材料
  - trusted public key 不匹配
- 两个场景均使用 `schedule_meeting`，因为业务副作用可通过 calendar oracle 直接观察。

场景 1：缺失签名材料

- 命令：
  - `.venv/bin/python experiments/batch_run.py --task schedule_meeting --initiator-config user_configs/emma.yaml --receiver-config user_configs/raj_pqcan.yaml --skip-model-probe --allow-task-failure --query-timeout 300`
- 运行目录：`experiments/runs/20260520T120753Z-schedule_meeting/`
- 结果：
  - query record: `success=false`, `oracle_reason=no_matching_event_found`, `runtime_auth_enabled=false`
  - receiver side: `runtime_auth_enabled=true`
  - receiver audit: `reason=missing_request_envelope`
  - `has_request_envelope=false`, `has_pq_signature=false`
  - `local_run_count=0`, `peer_run_count=0`
  - `self_upcoming_event_count=0`, `peer_upcoming_event_count=0`

场景 2：trusted public key 不匹配

- 新增负向 fixture：`user_configs/raj_pqcan_bad_trust.yaml`
  - 与 `raj_pqcan.yaml` 的唯一差异是 calendar agent 中对 `emma_johnson@gmail.com:calendar_agent` 的 `trusted_public_keys` 值。
  - 该值仍为合法 base64 公钥字节，但不是 Emma calendar agent 对应的 signing key。
- 命令：
  - `.venv/bin/python experiments/batch_run.py --task schedule_meeting --initiator-config user_configs/emma_pqcan.yaml --receiver-config user_configs/raj_pqcan_bad_trust.yaml --skip-model-probe --allow-task-failure --query-timeout 300`
- 运行目录：`experiments/runs/20260520T121114Z-schedule_meeting/`
- 结果：
  - query record: `success=false`, `oracle_reason=no_matching_event_found`, `runtime_auth_enabled=true`
  - receiver audit 新增：`reason=signature_verification_failed`
  - `has_request_envelope=true`, `has_pq_signature=true`
  - `local_run_count=0`, `peer_run_count=0`
  - `self_upcoming_event_count=0`, `peer_upcoming_event_count=0`

本轮测试：

- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_encoding.py tests/test_execution_gate.py tests/integration/test_baseline_agent_flow.py tests/test_schedule_meeting.py` -> `51 passed`

说明：

- 本轮没有重新运行完整三任务正向批跑；H6 已在上一 checkpoint 完成。
- 负向批跑使用 `--allow-task-failure` 是为了让 query 失败作为预期结果保留，同时仍让 runner 正常清理 listener/provider/mongo。
- 受限 sandbox 内启动 `mongod` 会因 `set_option: Operation not permitted` 失败；真实负向场景均在外部权限下执行。

### 2026-05-22 Execution-Surface Documentation / Negative Matrix Session

目标：

- 按当前工作文档的下一步，先收口四项工作：
  - 保持正式 `experiments/results/*.jsonl` 与运行产物不进入版本库
  - 整理 checkpoint 摘要
  - 补 `SECURITY.md` / README 的安全边界说明
  - 补 execution gate 与 ML-DSA adapter 的关键缺口测试

已做工作：

- 当时新增备用方案草稿：
  - `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md`
  - 后续已在 `2026-05-23` 合并进主工作文档并删除原文件
- 新增安全文档：
  - `SECURITY.md`
  - 明确 SAGA 负责协议层准入，PQ-CAN 负责 receiving-side execution-surface authorization
  - 明确 toy LWE 只用于 research wiring / tests
  - 明确 `MLDSAAdapter` 只能包装外部审查过的 ML-DSA backend
  - 记录负向安全测试矩阵
- 更新 README：
  - 增加 execution-surface authorization 边界说明
  - 明确 Agent-LLM 输出只能请求 scope / 表达 intent，不能作为可信授权证明
- 更新 `.gitignore`：
  - 新增 `saga/user/*/audit/`
  - 当前 `saga/user/raj.sharma@gmail.com:calendar_agent/audit/` 已被识别为 ignored 运行产物
- 改进 `pq/mldsa_adapter.py`：
  - 从纯 stub 调整为 fail-closed 外部 backend adapter
  - 无 backend 时明确报错
  - backend 形状不完整时明确报错
  - backend 存在时仅委托 `keygen/sign/verify`，不在仓库内实现 ML-DSA
- 扩展测试：
  - `tests/test_toy_lwe.py`
    - 覆盖 ML-DSA adapter 无 backend fail-closed
    - 覆盖显式 backend 委托路径
    - 覆盖畸形 backend 拒绝
  - `tests/test_execution_gate.py`
    - 覆盖 `untrusted_sender_aid`
    - 覆盖 `sender_aid_mismatch`
    - 覆盖 `receiver_aid_mismatch`
    - 覆盖 `token_digest_mismatch`
    - 覆盖 `invalid_request_envelope`

测试结果：

- `.venv/bin/python -m pytest -q tests/test_toy_lwe.py tests/test_execution_gate.py tests/test_agent_wrapper_gate.py` -> `37 passed`
- `.venv/bin/python -m pytest -q` -> `159 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `15 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `.gitignore`
- `README.md`
- `SECURITY.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md`（后续已在 `2026-05-23` 合并进主工作文档并删除）
- `pq/mldsa_adapter.py`
- `tests/test_toy_lwe.py`
- `tests/test_execution_gate.py`

不纳入 checkpoint / push 的本地运行产物：

- `experiments/results/`
- `experiments/runs/`
- `saga/user/*/audit/`
- `saga/user/*/diagnostics/`
- `saga/user/*/`
- `saga/ca/*.crt|*.key|*.pub`
- `saga/provider/*.crt|*.key|*.pub`
- `.mongodb/`
- `.mongodata/`

说明：

- 本次未重新运行真实 LLM-backed 三任务或负向 batch；只补文档、adapter 和自动化测试矩阵。
- 当前改动不包含私钥、生成证书、本地 DB、实验结果或模型输出。

### 2026-05-23 Backup Execution-Surface Plan Merge Session

目标：

- 将 `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md` 合并进主工作文档。
- 在合并时明确区分已经完成的工作与未来继续项。
- 合并完成后删除备份计划文件，避免后续出现多个事实来源。

已做工作：

- 更新 `SAGA_PQ_CAN_WORKLOG.md`：
  - 新增 `2.4 论文与架构主线`
  - 将主线明确为 `Execution-Surface Authorization for Agent Runtimes + Policy-aware Agent-LLM interface`
  - 明确最终授权公式：
    `allow = saga_token_valid AND request_envelope_valid AND pq_signature_valid AND can_accept AND execution_scope_allowed AND internal_policy_accept`
  - 将 `pq_signature` 明确为 detached signature，不进入 canonical request envelope
  - 在当前状态面板中单列 execution-surface authorization 已完成能力和后续补强能力
  - 更新 Phase 5 / Phase 6，把 prompt gate、policy-aware intent layer、负向矩阵、消融与 overhead 统计纳入后续路线
  - 在任务看板中新增/更新 F7-F10、G9、H9-H12 和 I 组任务
  - 更新当前工作焦点和下一步，明确优先做 prompt gate、replay 防护、intent/compiler 层和负向注入 runner
- 删除 `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md`。

已完成能力归档：

- request envelope、detached signature、toy LWE gate、Shamir STEP/RECT/MASK、execution gate audit、tool/memory/delegation 第一版 gate、fail-closed ML-DSA adapter、PQ-CAN 正向三任务真实通过、两个最小负向场景真实通过。

未来继续项：

- 独立 prompt gate。
- replay seen-request 状态管理。
- `AgentIntent / PolicyDecision / IntentCompiler` 语义层。
- `toy mode / compiled research mode / ML-DSA mode` 运行模式拆分。
- 负向注入 runner。
- 论文级消融对比与 overhead 统计。

测试说明：

- 本次只合并和删除文档，没有修改源码。
- 已按仓库规则重新运行：
  - `.venv/bin/python -m pytest -q` -> `159 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `15 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md` deletion

### 2026-05-23 Fixed-Circuit Runtime-Gate Plan Update

目标：

- 按当前讨论，把验签神经元固定电路化和 Agent runtime 强制路径写入主工作文档。
- 不把周报概括段落写入工作文档。

已做工作：

- 更新 `SAGA_PQ_CAN_WORKLOG.md`：
  - 在项目范围中明确验签神经元必须作为 `requires_grad=False` 固定神经电路运行。
  - 明确固定电路只接收公开信息：`public_key_bits || canonical_envelope_digest_bits || signature_bits`。
  - 明确 Agent runtime 安全模式下 `LLM prompt / tool executor / memory read-write / delegation` 都必须经过已验签的 `LocalExecutionContext`。
  - 明确 LLM 只能建议 `requested_scopes` / capability intent，不能决定授权或扩大 signed envelope 中的授权范围。
  - 在 Phase 4 中补充 compiled verifier / DNN / CNN / CAN 的冻结参数和无训练入口约束。
  - 在 Phase 5 中补充安全模式 fail-closed、双向 inbound turn 验签、base tools 包装或禁用、scope escalation 审计要求。
  - 在任务看板中新增 E9-E10、F11-F14。
  - 更新当前工作焦点和下一步，将固定电路检查、prompt gate、安全模式强制 gate、initiating-side response 验签列为优先事项。

测试说明：

- 本次只调整工作文档，没有修改源码。
- 本次未重新运行测试；上一次完整记录仍为：
  - `.venv/bin/python -m pytest -q` -> `159 passed, 21 subtests passed`
  - `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
  - `.venv/bin/python -m pytest -q tests/integration` -> `15 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行对应命令。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SAGA_PQ_CAN_BACKUP_EXEC_SURFACE_PLAN.md` deletion（来自前一轮文档合并状态，非本次新增源码变更）

### 2026-05-27 Fixed-Circuit Audit / Prompt Surface Gate Session

目标：

- 按当前下一步继续推进固定电路检查与独立 prompt execution surface gate。
- 保持改动小范围、可回归，不触碰真实实验运行产物和生成凭据。

已做工作：

- 新增 `neural/fixed_circuit.py`：
  - `TrainableStateFinding`
  - `find_trainable_state(...)`
  - `assert_fixed_circuit(...)`
  - 递归检查 `requires_grad=True`、`trainable=True` 与 PyTorch 风格可训练 `Parameter`
- 更新 `neural/can.py` / `neural/compiled_lwe_dnn.py`：
  - 为 `CAN`、`CompiledToyLWEVerifier`、`FixedEqualityAggregator` 暴露 `submodules()`
  - 便于固定电路审计递归遍历关键子模块
- 更新 `tests/test_compiled_lwe_dnn.py`：
  - 覆盖 compiled verifier 无可训练状态
  - 覆盖 `CAN(compiled verifier)` 组合无可训练状态
  - 覆盖审计 helper 能发现嵌套可训练子模块
- 更新 `saga/agent.py`：
  - 抽出 `_build_execution_gate_request(...)`
  - 新增 `_evaluate_prompt_surface_request(...)`
  - receiving-side 在 `local_agent.run()` 前显式要求 `LocalExecutionContext` 授权 `llm_prompt`
  - 仅有 `tool_call:*` scope 的 signed envelope 会被拒绝并审计为 `prompt_scope_not_authorized`
  - 新增 `strict_execution_gate` 安全模式；PQ-CAN runtime auth 默认开启 strict
  - strict 模式下缺失 `execution_gate` / `LocalExecutionContext` 分别以 `missing_execution_gate` / `missing_local_execution_context` 拒绝
- 更新 `saga/config.py`：
  - `ToyRuntimeAuthConfig` 新增 `strict_execution_gate=True`
  - 配置可显式关闭 strict 以做 legacy compatibility 测试
- 更新 `tests/integration/test_baseline_agent_flow.py`：
  - 将原“tool scope 入口可进入 local_agent.run”用例改为 prompt 入口携带 signed tool scope
  - 新增 tool-only envelope 不能进入 LLM prompt surface 的负向集成测试
  - 新增 strict 模式缺 gate/context 的 fail-closed 集成测试
- 更新 `tests/test_agent_runtime_auth.py` / `tests/test_runtime_auth_configs.py`：
  - 验证 runtime auth 默认启用 strict execution gate
  - 验证配置可显式关闭 strict 兼容模式
- 更新本工作文档：
  - 将 E9 标记为 `已完成`
  - 将 F8 标记为 `已完成`
  - 将 F11 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步与测试结果

测试结果：

- `.venv/bin/python -m pytest -q tests/test_compiled_lwe_dnn.py tests/test_can.py tests/test_shamir_layers.py` -> `25 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py tests/test_execution_gate.py tests/test_agent_runtime_auth.py` -> `40 passed`
- `.venv/bin/python -m pytest -q` -> `166 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `18 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `neural/__init__.py`
- `neural/can.py`
- `neural/compiled_lwe_dnn.py`
- `neural/fixed_circuit.py`
- `saga/config.py`
- `saga/agent.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/test_agent_runtime_auth.py`
- `tests/test_compiled_lwe_dnn.py`
- `tests/test_runtime_auth_configs.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改源码、测试和工作文档。

GitHub / checkpoint 状态：

- 本轮已完成 `git status --short` 检查，工作区仅包含上述源码/测试/文档改动。
- 下一步准备形成本地 checkpoint；若远程权限与网络允许，可推送到 `backup/<current-branch>`，不得推送到主开发分支。

### 2026-05-27 Policy-Aware Intent Compiler Session

目标：

- 完成 I1-I4 的最小版本：将 LLM / runtime requested scopes 建模为 proposal，而不是授权来源。
- 让 signed `authorized_scopes` 来自本地 policy 与 requested scopes 的交集。

已做工作：

- 新增 `saga/intent.py`：
  - `AgentIntent`
  - `PolicyDecision`
  - `IntentCompiler`
  - `IntentCompiler.compile(...)` 将 untrusted requested scopes 编译为本地 policy 允许的 signed scopes
- 更新 `saga/agent.py`：
  - `_conversation_authorized_scopes(...)` 新增 `requested_scopes` 参数
  - 默认仍从本地 `tool_collections` 生成可签名工具 scope
  - requested scopes 只作为 proposal；未暴露工具、`memory_write`、`delegation` 不会进入 signed envelope
- 新增 `tests/test_intent.py`：
  - 覆盖 requested scopes 与本地 policy 取交集
  - 覆盖 broad tool policy 可授权 qualified tool request
  - 覆盖非法 requested scope 在构造 intent 时拒绝
- 更新 `tests/integration/test_baseline_agent_flow.py`：
  - 覆盖 `Agent._conversation_authorized_scopes(...)` 不会被 requested scopes 扩权
- 更新本工作文档：
  - 将 I1-I4 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步与测试结果

测试结果：

- `.venv/bin/python -m pytest -q tests/test_intent.py tests/test_encoding.py tests/test_agent_runtime_auth.py tests/integration/test_baseline_agent_flow.py` -> `43 passed`
- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_execution_gate_factory.py tests/integration/test_experiment_runtime_auth_entrypoints.py tests/test_runtime_auth_configs.py` -> `34 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q` -> `177 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `saga/agent.py`
- `saga/intent.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/test_intent.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改源码、测试和工作文档。

GitHub / checkpoint 状态：

- 本轮已完成 `git status --short` 检查，工作区仅包含上述源码/测试/文档改动。
- 下一步准备形成本地 checkpoint；若远程权限与网络允许，可推送到 `backup/<current-branch>`，不得推送到主开发分支。

### 2026-05-27 Replay Seen-Request Session

目标：

- 完成 F9：为执行路径增加 seen-request replay 状态管理。
- 重复使用同一个 signed envelope/session/turn 时必须拒绝，并且不触发本地 agent。

已做工作：

- 更新 `saga/execution_gate.py`：
  - `SignedRequestExecutionGate` 新增 `_seen_request_ids`
  - 新增 `consume_request(...)`，执行 validate-and-consume 语义
  - 同一 envelope digest 重复消费时返回 `replayed_request_envelope`
  - 新增 `build_local_execution_context_from_decision(...)`，避免 consume 后为了构造 context 再次验签/误判 replay
  - `evaluate_request(...)` 保持纯检查，不改变 replay 状态
- 更新 `saga/agent.py`：
  - `_evaluate_execution_request(..., consume=True)` 在实际执行路径调用 `consume_request(...)`
  - receiving-side request 与 initiating-side inbound response 均改为执行前消费 envelope
  - `_build_local_execution_context(...)` 可从已授权 decision 直接构造 context
- 更新 `tests/test_execution_gate.py`：
  - 覆盖同一 envelope 第二次 `consume_request(...)` 被 `replayed_request_envelope` 拒绝
  - 覆盖 `evaluate_request(...)` 不消费 replay 状态
- 更新 `tests/integration/test_baseline_agent_flow.py`：
  - 覆盖 receiving-side 同一 signed envelope 第二次进入时被 replay 拒绝
  - 断言 replay 拒绝不会第二次触发本地 agent
- 更新本工作文档：
  - 将 F9 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步与测试结果

测试结果：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_execution_gate_factory.py tests/integration/test_baseline_agent_flow.py` -> `47 passed`
- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `11 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q` -> `173 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `23 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `saga/agent.py`
- `saga/execution_gate.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/test_execution_gate.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改源码、测试和工作文档。

GitHub / checkpoint 状态：

- 本轮已完成 `git status --short` 检查，工作区仅包含上述源码/测试/文档改动。
- 下一步准备形成本地 checkpoint；若远程权限与网络允许，可推送到 `backup/<current-branch>`，不得推送到主开发分支。

### 2026-05-27 Initiating-Side Response Gate Session

目标：

- 继续完成 F12：initiating side inbound response 也必须执行 `request_envelope / pq_signature / CAN` 验签。
- 保证 peer response 验签失败时不会触发 initiating-side `local_agent.run()`。

已做工作：

- 更新 `saga/agent.py`：
  - 新增 `_record_execution_gate_rejection(...)`，统一 receiving-side request 与 initiating-side response 的审计落盘逻辑
  - 在 `Agent.initiate_conversation(...)` 收到 response 后、读取响应正文并调用本地 agent 前执行 execution gate
  - response gate 使用 `sender_aid=r_aid`、`receiver_aid=self.aid`、同一 token 和 response payload 中的 `request_envelope / pq_signature`
  - response gate 通过后构造 `LocalExecutionContext` 并传给 initiating-side `local_agent.run()`
  - strict 模式下缺失 envelope/signature、message digest mismatch、wrong trusted key 等拒绝均不会触发本地 agent
  - `_evaluate_execution_request(...)` / `_build_local_execution_context(...)` 改用 `getattr(..., None)`，兼容旧测试中通过 `Agent.__new__` 构造的 shell 对象
- 更新 `tests/integration/test_baseline_agent_flow.py`：
  - 新增 valid signed response 继续执行 initiating-side local agent 的测试
  - 新增 missing response envelope/signature 拒绝测试
  - 新增 tampered response message 拒绝测试
  - 新增 wrong trusted key 拒绝测试
  - 上述负向测试均断言 local agent 未运行，并检查稳定 audit reason
- 更新本工作文档：
  - 将 F12 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步与测试结果

测试结果：

- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/test_agent_runtime_auth.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `33 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q` -> `170 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `22 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `saga/agent.py`
- `tests/integration/test_baseline_agent_flow.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改源码、测试和工作文档。

GitHub / checkpoint 状态：

- 本轮已完成 `git status --short` 检查，工作区仅包含上述源码/测试/文档改动。
- 下一步准备形成本地 checkpoint；若远程权限与网络允许，可推送到 `backup/<current-branch>`，不得推送到主开发分支。

### 2026-05-27 Negative Injection Runner Session

目标：

- 完成 H9：新增离线负向注入 runner。
- 覆盖 tampered message/scope、expired/replayed envelope、unauthorized tool/memory/delegation、real-valued input、untrusted sender key。

已做工作：

- 新增 `experiments/negative_injection_runner.py`：
  - 离线构造 deterministic toy LWE signed request envelope，不启动 MongoDB / Provider / 模型后端
  - 默认覆盖 11 个负向场景：
    - `tampered_message`
    - `tampered_action_scope`
    - `tampered_authorized_scope`
    - `expired_envelope`
    - `replayed_envelope`
    - `unauthorized_tool_scope`
    - `unauthorized_memory_write`
    - `unauthorized_delegation`
    - `real_valued_signature_input`
    - `untrusted_sender_aid`
    - `wrong_trusted_sender_key`
  - 输出 `negative_injections.jsonl` 与 `negative_injections_summary.json`
  - 任一场景未按预期 fail-closed 时 CLI 返回非零
- 新增 `tests/test_negative_injection_runner.py`：
  - 覆盖默认场景清单
  - 覆盖全量默认场景均 PASS
  - 覆盖 tool / memory / delegation 越权场景不会触发副作用
  - 覆盖 JSONL / summary 输出
  - 覆盖 CLI 失败结果返回非零
- 更新 `SECURITY.md`：
  - 记录离线负向注入 runner 的命令、输出文件和防御性测试边界
- 更新本工作文档：
  - 将 H9 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步

测试结果：

- `.venv/bin/python -m pytest -q tests/test_negative_injection_runner.py` -> `5 passed`
- `.venv/bin/python experiments/negative_injection_runner.py --output-dir /tmp/saga-negative-runner-smoke` -> `11/11` scenarios passed
- `.venv/bin/python -m pytest -q` -> `182 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/negative_injection_runner.py`
- `tests/test_negative_injection_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次新增 runner 的 smoke 输出写入 `/tmp/saga-negative-runner-smoke`，不进入仓库提交范围。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 本轮已完成 `git status --short` 检查，工作区仅包含上述源码/测试/文档改动。
- 本轮待提交文件不包含 secrets、生成凭据、本地 DB、模型输出或 `paper/`。
- 本轮已形成本地 checkpoint：
  - commit: `8bf2dbf checkpoint: add negative injection runner`
- 备份推送到 `origin/backup/repro-local` 失败：
  - `Bad owner or permissions on /etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf`
  - 这是本机 SSH 配置权限问题；本轮只保留本地 checkpoint，未推送主开发分支。

### 2026-05-27 Runtime Negative Injection Runner Session

目标：

- 完成 H10：把 prompt surface / replay / execution-scope escalation 扩展成真实 `Agent.receive_conversation(...)` runtime-path 负向样本。
- 保持样本离线、确定性，不启动 MongoDB / Provider / 模型后端。

已做工作：

- 更新 `experiments/negative_injection_runner.py`：
  - 新增 `_RuntimeLocalAgent` 与 `_ScopeEscalatingLocalAgent` stub，用于记录 runtime 副作用
  - 新增真实 `Agent.receive_conversation(...)` 路径场景：
    - `agent_runtime_prompt_surface_tool_only`
    - `agent_runtime_replayed_envelope`
    - `agent_runtime_scope_escalation_tool`
  - `agent_runtime_prompt_surface_tool_only` 验证 tool-only envelope 在 prompt surface 前以 `prompt_scope_not_authorized` 拒绝，且 `local_agent.run()` 未触发
  - `agent_runtime_replayed_envelope` 验证同一 envelope 第二次进入真实执行路径时以 `replayed_request_envelope` 拒绝，且不会第二次触发本地 agent
  - `agent_runtime_scope_escalation_tool` 验证 prompt 已授权但未签名工具 scope 时，下游工具 scope escalation 以 `unauthorized_tool_scope` 拒绝，且没有记录工具副作用
- 更新 `tests/test_negative_injection_runner.py`：
  - 默认场景清单新增 3 个 `agent_runtime_*` 场景
  - 新增 runtime-path 场景测试，断言拒绝原因和无副作用
- 更新本工作文档：
  - 将 H10 标记为 `已完成`
  - 更新当前状态、当前焦点、当前下一步

测试结果：

- `.venv/bin/python -m pytest -q tests/test_negative_injection_runner.py` -> `6 passed`
- `.venv/bin/python experiments/negative_injection_runner.py --output-dir /tmp/saga-negative-runner-runtime-smoke` -> `14/14` scenarios passed
- `.venv/bin/python -m pytest -q` -> `183 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `experiments/negative_injection_runner.py`
- `tests/test_negative_injection_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次 smoke 输出写入 `/tmp/saga-negative-runner-runtime-smoke`，不进入仓库提交范围。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 待 `git status --short` 后整理最终 checkpoint。

### 2026-05-27 Chinese Comment Prefix Cleanup Session

目标：

- 按用户要求移除代码注释和 docstring 中不美观的中文提示前缀。
- 后续新增中文注释不再使用该前缀。

已做工作：

- 全局扫描并移除该中文提示前缀。
- 涉及文件包括：
  - `saga/agent.py`
  - `saga/execution_gate.py`
  - `saga/messages.py`
  - `saga/intent.py`
  - `neural/*`
  - `pq/mldsa_adapter.py`
  - `experiments/negative_injection_runner.py`
  - `experiments/ablation_overhead_runner.py`
  - 相关测试文件
  - `SAGA_PQ_CAN_DESIGN.md`
- 已确认该前缀无残留。
- 本次为机械注释/docstring 风格清理，不改变运行逻辑。

测试结果：

- `.venv/bin/python -m pytest -q` -> `187 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_DESIGN.md`
- `experiments/ablation_overhead_runner.py`
- `experiments/negative_injection_runner.py`
- `neural/can.py`
- `neural/compiled_lwe_dnn.py`
- `neural/fixed_circuit.py`
- `pq/mldsa_adapter.py`
- `saga/agent.py`
- `saga/execution_gate.py`
- `saga/intent.py`
- `saga/messages.py`
- `tests/test_ablation_overhead_runner.py`
- `tests/test_execution_gate.py`
- `tests/test_negative_injection_runner.py`
- `tests/test_toy_lwe.py`
- `SAGA_PQ_CAN_WORKLOG.md`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改注释、docstring 和工作文档。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 待 `git status --short` 后整理最终 checkpoint。

### 2026-05-27 Offline Ablation / Overhead Runner Session

目标：

- 启动 H11/H12：新增第一版离线消融对比与本地认证组件微开销统计。
- 比较 `SAGA only / ordinary PQ middleware / naive neural / Shamir-secured PQ-CAN` 的安全覆盖差异。

已做工作：

- 新增 `experiments/ablation_overhead_runner.py`：
  - 不启动 MongoDB / Provider / 模型后端
  - 构造 deterministic signed envelope 与固定正/负样本
  - 消融模式：
    - `saga_only`
    - `ordinary_pq_middleware`
    - `naive_neural_verifier`
    - `shamir_secured_pq_can`
  - 消融样本：
    - `valid_prompt`
    - `tampered_message`
    - `expired_envelope`
    - `prompt_surface_tool_only`
    - `unauthorized_tool_scope`
    - `real_valued_signature_input`
  - 开销指标：
    - `toy_sign`
    - `ordinary_pq_verify`
    - `compiled_verifier`
    - `shamir_can`
    - `execution_gate_evaluate`
  - 输出：
    - `ablation_results.jsonl`
    - `overhead_results.json`
    - `ablation_overhead_summary.json`
- 新增 `tests/test_ablation_overhead_runner.py`：
  - 覆盖各模式安全差异
  - 覆盖 per-mode negative rejection summary
  - 覆盖开销指标名称与迭代次数
  - 覆盖 JSON / JSONL 结果落盘
- 更新 `SECURITY.md`：
  - 记录离线消融/开销 runner 命令、比较模式、指标范围和“真实 API cost 需另测”的限制
- 更新本工作文档：
  - 将 H11/H12 标记为 `部分完成`
  - 说明当前为离线微基准，真实任务端到端 latency / API cost / model call count 仍需后续补齐

测试结果：

- `.venv/bin/python -m pytest -q tests/test_ablation_overhead_runner.py` -> `4 passed`
- `.venv/bin/python experiments/ablation_overhead_runner.py --iterations 5 --output-dir /tmp/saga-ablation-overhead-smoke` -> completed
  - `saga_only`: `passed=1/6`, `negative_rejected=0`
  - `ordinary_pq_middleware`: `passed=3/6`, `negative_rejected=2`
  - `naive_neural_verifier`: `passed=3/6`, `negative_rejected=2`
  - `shamir_secured_pq_can`: `passed=6/6`, `negative_rejected=5`
- `.venv/bin/python -m pytest -q` -> `187 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/ablation_overhead_runner.py`
- `tests/test_ablation_overhead_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次 smoke 输出写入 `/tmp/saga-ablation-overhead-smoke`，不进入仓库提交范围。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 待 `git status --short` 后整理最终 checkpoint。

### 2026-05-27 Engineering Rule Update Session

目标：

- 按用户要求补充工程规则：新增或修改中文注释/docstring 时，不使用 `中文：` 这类语言标签前缀，直接写自然中文说明。

已做工作：

- 更新根目录 `AGENTS.md` 的中英文工程规则。
- 同步更新 `saga/AGENTS.md` 的中英文工程规则，避免子目录规则与仓库级规则不一致。
- 更新本工作文档中的当前状态、任务看板、当前焦点与工作日志。

测试结果：

- `python -m pytest -q` -> 未运行成功，当前环境没有 `python` 命令。
- `.venv/bin/python -m pytest -q` -> `187 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `AGENTS.md`
- `saga/AGENTS.md`
- `SAGA_PQ_CAN_WORKLOG.md`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只修改工程规则与工作文档。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 当前仅保留工作区改动与本地 checkpoint 摘要，未执行提交或推送。

### 2026-05-27 Batch Completion Recovery Session

目标：

- 从上下文中断点恢复，确认 `PQ-CAN` batch 最后一项 `create_blogpost` 是否完成。
- 区分真实模型/工具行为差异与 PQ-CAN gate 拒绝，避免误归类。

已确认结果：

- 最新 PQ-CAN 三任务 batch 已完成：
  - 运行目录：`experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/`
  - `end_to_end_stats_summary.json`: `succeeded_count=3`, `failed_count=0`
  - `schedule_meeting`: `success=true`, `runtime_auth_enabled=true`, `oracle_reason=meeting_scheduled`
  - `expense_report`: `success=true`, `runtime_auth_enabled=true`
  - `create_blogpost`: `success=true`, `runtime_auth_enabled=true`
- `create_blogpost` 已保存目标 markdown 文档并返回 `<TASK_FINISHED>`。
- `expense_report` 日志中的 `submit_expense_report` permission gate 是模型/工具层行为差异；业务 oracle 最终成功，`peer_audit_reject_count=0`，不作为 PQ-CAN gate 拒绝。
- `create_blogpost` 日志中的 code parsing retry 是模型输出格式重试；最终任务成功，`peer_audit_reject_count=0`，不作为 PQ-CAN gate 拒绝。
- 最新 baseline 对照 batch 也已完成：
  - 运行目录：`experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/`
  - `end_to_end_stats_summary.json`: `succeeded_count=3`, `failed_count=0`

测试结果：

- `.venv/bin/python -m pytest -q` -> `192 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `AGENTS.md`
- `saga/AGENTS.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/batch_run.py`
- `experiments/create_blogpost.py`
- `experiments/expense_report.py`
- `experiments/result_logging.py`
- `experiments/schedule_meeting.py`
- `saga/agent.py`
- `saga/runtime_diagnostics.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/integration/test_experiment_runtime_auth_entrypoints.py`
- `tests/test_batch_run.py`
- `tests/test_result_logging.py`
- `tests/test_runtime_diagnostics.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 最新真实运行产物位于 ignored `experiments/runs/` 与 `experiments/results/`，不进入 checkpoint。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 待 `git status --short` 后形成最终 checkpoint。

### 2026-05-27 Real End-to-End Stats Session

目标：

- 把 H11/H12 从离线微基准扩展到真实任务端到端统计。
- 在三任务真实 query 结果中记录 task latency、API cost、model call count、audit/logging overhead。

已做工作：

- 新增 `experiments.result_logging.collect_query_execution_stats(...)` 与 `summarize_end_to_end_task_stats(...)`：
  - 汇总本地/对端 runtime diagnostics
  - 汇总本地/对端 execution-gate audit 记录
  - 生成 task latency、model call count、LLM elapsed、audit record count、logging stats collection latency 字段
  - API cost / token usage 只汇总已有显式字段；当前未暴露时标记 unavailable
- 更新 `saga/runtime_diagnostics.py`：
  - 每条 local run 诊断新增 `model_call_count`
  - 该字段按新增非 `TaskStep` / `SystemPromptStep` memory step 估算真实模型调用步数
  - 旧诊断缺字段时，端到端统计回退到已结束 local-agent run 次数
- 更新三个真实任务入口：
  - `experiments/schedule_meeting.py`
  - `experiments/expense_report.py`
  - `experiments/create_blogpost.py`
  - query 模式会把端到端统计字段写入 `experiments/results/<task>.jsonl`
- 更新 `experiments/batch_run.py`：
  - 每个任务 query 后读取当前新增结果记录
  - run 目录写入 `end_to_end_stats_summary.json`
  - 汇总 task latency、model call count、audit/logging 统计、API cost 可用性
- 更新 `SECURITY.md`：
  - 记录真实 batch run 的端到端统计产物和 API cost 保守语义
- 新增/更新测试：
  - `tests/test_result_logging.py`
  - `tests/test_batch_run.py`
  - `tests/integration/test_experiment_runtime_auth_entrypoints.py`

测试结果：

- `.venv/bin/python -m pytest -q tests/test_result_logging.py` -> `7 passed`
- `.venv/bin/python -m pytest -q tests/test_batch_run.py` -> `9 passed`
- `.venv/bin/python -m pytest -q tests/test_runtime_diagnostics.py` -> `4 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `4 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q` -> `192 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `AGENTS.md`
- `saga/AGENTS.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/batch_run.py`
- `experiments/create_blogpost.py`
- `experiments/expense_report.py`
- `experiments/result_logging.py`
- `experiments/schedule_meeting.py`
- `saga/runtime_diagnostics.py`
- `tests/integration/test_experiment_runtime_auth_entrypoints.py`
- `tests/test_batch_run.py`
- `tests/test_result_logging.py`
- `tests/test_runtime_diagnostics.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实模型 batch run，未生成新的 `experiments/runs/` 产物。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 当前仅保留工作区改动与本地 checkpoint 摘要，未执行提交或推送。

### 2026-05-27 Final Checkpoint Closure

目标：

- 结束恢复会话前记录最终 checkpoint 与备份分支状态。

已完成：

- 已创建本地 checkpoint commit，并推送到备份分支：
  - `origin/backup/repro-local`
- 未推送到主开发分支。
- 最终检查以 `git log -1 --oneline --decorate` 与 `git status --short --branch` 为准；`repro-local` 相对 `origin/repro-local` 仍保留本地 checkpoint 序列，后续合并回常规开发分支需单独处理。

敏感文件审查：

- checkpoint 文件范围只包含源码、测试与文档。
- 未提交 `experiments/runs/`、`experiments/results/`、本地 DB、生成凭据、模型 checkpoint 或 `paper/`。

### 2026-05-27 F13 CodeAgent Base Tools Session

目标：

- 完成 F13：禁用或统一包装 `CodeAgent(add_base_tools=True)` 自动注入工具，避免未包装工具绕过 tool gate。

已做工作：

- 更新 `agent_backend/base.py`：
  - `CodeAgentWrapper._create_local_agent_object(...)` 现在以 `add_base_tools=False` 创建 `CodeAgent`
  - 运行时业务工具只来自 `LocalAgentConfig.tools` 对应的显式工具集合
  - 显式工具继续由 `_wrap_tool_with_execution_gate(...)` 在执行前检查 `tool_call:<tool_name>`
  - 内置代码执行器保留为 CodeAgent prompt execution 机制，不作为额外 tool grant 写入 signed scopes
- 更新 `tests/test_agent_wrapper_gate.py`：
  - 新增回归测试，patch `agent_backend.base.CodeAgent` 并断言 `add_base_tools=False`
  - 继续覆盖工具 scope 匹配、scope 不匹配、memory/delegation helper 的 fail-closed 行为
- 更新 `SECURITY.md`：
  - 记录 `CodeAgent` 不得自动注入未包装 `smolagents` base tools 的安全不变量
- 更新本工作文档：
  - F13 标记为 `已完成`
  - 当前下一步收敛到 I5 审计语义与真实负向样本升级

测试结果：

- `.venv/bin/python -m pytest -q tests/test_agent_wrapper_gate.py` -> `9 passed`
- `.venv/bin/python -m pytest -q tests/test_agent_backend_config.py` -> `3 passed, 9 subtests passed`
- `.venv/bin/python -m pytest -q tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `4 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py` -> `20 passed`
- `.venv/bin/python -m pytest -q tests/test_result_logging.py tests/test_batch_run.py tests/test_runtime_diagnostics.py` -> `20 passed`
- `.venv/bin/python -m pytest -q` -> `193 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `agent_backend/base.py`
- `tests/test_agent_wrapper_gate.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实模型 batch run，未生成新的 `experiments/runs/` 产物。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 本小节随本轮 checkpoint commit 一起提交，并在安全检查通过后推送到 `origin/backup/repro-local`；最终提交以 `git log -1 --oneline --decorate` 为准。

### 2026-05-30 I5 Stable Policy / Tool Reason Session

目标：

- 完成 I5：补稳定 `scope_escalation / tool_not_authorized / policy_reject` 语义，区分模型/工具 permission failure 与 PQ-CAN gate reject。

已做工作：

- 更新 `saga/intent.py`：
  - `IntentCompiler.compile(...)` 现在在入口动作被 policy 拒绝时返回 `policy_reject`
  - requested scopes 额外越权时返回 `scope_escalation`
- 更新 `saga/execution_gate.py`：
  - 新增 `ExecutionAuthorizationError`
  - 新增 `reason_for_unauthorized_scope(...)`
  - `LocalExecutionContext.require_*` 现在携带稳定 `reason/action_scope`
- 更新 `agent_backend/base.py`：
  - 包装工具入口将本地工具权限失败统一为 `tool_not_authorized`
  - 该 reason 用于模型/工具层 permission failure，不写入 PQ-CAN signature-gate audit
- 更新 `saga/agent.py`：
  - 新增 `_conversation_policy_decision(...)`，保留原 `_conversation_authorized_scopes(...)` 行为
- 更新 `SECURITY.md`：
  - 记录 policy reject、scope escalation、tool permission failure 和底层 execution-surface failure 的边界。
- 更新测试：
  - `tests/test_intent.py`
  - `tests/test_execution_gate.py`
  - `tests/test_agent_wrapper_gate.py`
  - `tests/integration/test_baseline_agent_flow.py`

测试结果：

- `.venv/bin/python -m pytest -q tests/test_intent.py tests/test_execution_gate.py tests/test_agent_wrapper_gate.py` -> `39 passed`
- `.venv/bin/python -m pytest -q tests/test_negative_injection_runner.py tests/test_ablation_overhead_runner.py` -> `10 passed`
- `.venv/bin/python -m pytest -q tests/integration/test_baseline_agent_flow.py` -> `20 passed`
- `.venv/bin/python -m pytest -q` -> `196 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `agent_backend/base.py`
- `saga/agent.py`
- `saga/execution_gate.py`
- `saga/intent.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/test_agent_wrapper_gate.py`
- `tests/test_execution_gate.py`
- `tests/test_intent.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实模型 batch run，未生成新的 `experiments/runs/` 产物。

GitHub / checkpoint 状态：

- 已形成本地 checkpoint commit：
  - `ce6e4f3 checkpoint: close authorization formula`
- 已成功推送到备份分支：
  - `origin/backup/repro-local`
- 未推送到主开发分支或 `origin/repro-local`。

### 2026-05-30 Real-Service Negative Runner Session

目标：

- 将离线 runtime-path 负向样本升级为需要本地 CA / Provider / socket listener 的端到端真实服务样本。

已做工作：

- 新增 `experiments/real_negative_runner.py`：
  - 提供 `run / listen / query` 三个 CLI 模式
  - `run` 模式启动或复用本地 `MongoDB / CA file server / Provider`
  - `listen` 模式启动真实 receiving `Agent.listen()` socket listener
  - `query` 模式走真实 Provider access、token、TLS socket，只覆盖 handshake 后的 conversation payload 注入
  - 第一批场景覆盖 `missing_request_envelope` 与 `tampered_message`
  - 不依赖模型后端，receiver local agent 是记录型 stub；负向通过时不应触发 local run
  - 输出 `real_negative_results.jsonl` 与 `real_negative_summary.json` 到 ignored run 目录
- 新增 `tests/test_real_negative_runner.py`：
  - 覆盖支持场景清单
  - 覆盖 missing envelope / tampered message payload 构造
  - 覆盖 JSONL/summary 写入
  - 覆盖 listener/query 子进程命令构造
  - 覆盖 run 模式失败时返回非零状态
- 更新 `SECURITY.md`：
  - 记录 opt-in 真实服务负向 runner 的用法、边界和非模型后端语义。
- 更新本工作文档：
  - H13 标记为 `进行中`
  - 当前下一步改为 opt-in 真实运行一次 runner，并扩展更多真实服务场景。

已验证：

- `.venv/bin/python -m pytest -q tests/test_real_negative_runner.py tests/test_negative_injection_runner.py tests/test_batch_run.py` -> `21 passed`
- `.venv/bin/python experiments/real_negative_runner.py run --help` -> 成功
- `.venv/bin/python experiments/real_negative_runner.py listen --help` -> 成功
- `.venv/bin/python experiments/real_negative_runner.py query --help` -> 成功
- `.venv/bin/python -m pytest -q` -> `207 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/real_negative_runner.py`
- `tests/test_real_negative_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本轮未实际启动真实服务 run，只验证了 opt-in runner 的单元逻辑和 CLI help，未生成新的 `experiments/runs/` 产物。

GitHub / checkpoint 状态：

- 已形成本地 checkpoint commit：
  - `ce6e4f3 checkpoint: close authorization formula`
- 已形成日志 checkpoint commit：
  - `73071fb log: record authorization formula checkpoint`
- 已成功推送到备份分支：
  - `origin/backup/repro-local`
- 未推送到主开发分支或 `origin/repro-local`。

### 2026-05-31 E10 Fixed-Circuit Freeze Audit Session

目标：

- 完成 E10：明确 DNN/CNN/CAN 固定电路的冻结参数和无训练入口约束，并补自动化测试。

已做工作：

- 更新 `neural/fixed_circuit.py`：
  - 保留递归检查 `requires_grad=True`、`trainable=True` 和 PyTorch `Parameter(requires_grad=True)` 的已有能力
  - 新增对 PyTorch 风格 `parameters()` 迭代器的可训练参数检查
  - 新增对 `optimizer` / `optim` / `scheduler` 训练状态属性的检查
  - 新增对明确训练更新入口的检查：
    - `backward`
    - `configure_optimizers`
    - `fit`
    - `optimizer_step`
    - `train_step`
    - `training_step`
    - `zero_grad`
  - 不把普通 `train()` 模式切换方法视为训练更新入口，避免误报 PyTorch module API
- 新增 `tests/test_fixed_circuit.py`：
  - 覆盖 `STEP13` / `RECT13` / `MASK` 整体无可训练状态
  - 覆盖 `CompiledToyLWEVerifier` 和 `CAN` 在验签前后仍无可训练状态
  - 覆盖 `parameters()` 返回可训练参数会被报告
  - 覆盖 optimizer 状态和训练入口会被报告
  - 覆盖普通 `train()` 模式切换不误报
- 更新 `SECURITY.md`：
  - 明确 DNN/CNN/CAN verifier 是 compiled deterministic circuit，不是 trained classifier
  - 固定电路审计必须拒绝 trainable parameters、optimizer state 和 training-update entrypoints
- 更新本工作文档：
  - E10 标记为 `已完成`
  - 当前下一步切换到 E7 challenge 派生边界决策

已验证：

- `.venv/bin/python -m pytest -q tests/test_fixed_circuit.py tests/test_compiled_lwe_dnn.py tests/test_shamir_layers.py tests/test_can.py` -> `30 passed`
- `.venv/bin/python -m pytest -q` -> `222 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `neural/fixed_circuit.py`
- `tests/test_fixed_circuit.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。

### 2026-06-01 OTK AID Binding Session

目标：

- 完成 C4：将 OTK 签名语义从 raw OTK bytes 收紧为绑定 `aid + OTK`，避免同一用户签名的一次性公钥跨 agent 身份复用。

已做工作：

- 更新 `saga/common/crypto.py`：
  - 新增 `otk_signature_payload(...)`
  - 新增 `sign_otk(...)`
  - 新增 `verify_otk_signature(...)`
  - OTK 签名 payload 使用 domain-separated canonical JSON，包含 `domain / aid / otk`
- 更新 `saga/user/user.py`：
  - `register_agent(...)` 生成 OTK 签名时改为签名 `aid + OTK`
  - `refresh_otks(...)` 生成 OTK 签名时改为签名 `aid + OTK`
- 更新 `saga/provider/provider.py`：
  - `/register_agent` 按 AID-bound OTK payload 验签
  - `/refresh_otks` 按 AID-bound OTK payload 验签
  - raw OTK-only 旧签名不再被接受
- 更新 `saga/agent.py`：
  - initiating-side 使用 provider 返回 OTK 前按 `r_aid + OTK` 验签
  - receiving-side 本地 OTK 消费抽成 `_consume_local_otk(...)`，保持锁内原子消费，避免并发重复使用同一个 OTK
- 新增 `tests/security/test_otk_signature_binding.py`：
  - 覆盖 helper 对同一 OTK 的 AID 绑定
  - 覆盖 Provider 真实 `/register_agent` 路由接受 AID-bound OTK 签名
  - 覆盖 raw OTK-only 签名 fail closed
  - 覆盖 cross-AID OTK 签名 fail closed
  - 覆盖本地 OTK 并发消费最多只有一个成功
- 更新 `SECURITY.md`：
  - 记录 OTK 签名必须绑定 receiving agent identity
  - 将 raw OTK-only 与 cross-AID OTK 签名拒绝纳入负向覆盖
- 更新本工作文档：
  - C4 标记为 `已完成`
  - 当前下一步调整为 C5 / C6 与执行层安全补强

已验证：

- `.venv/bin/python -m pytest -q tests/security/test_otk_signature_binding.py` -> `5 passed`
- `.venv/bin/python -m pytest -q tests/security/test_token_validation.py tests/integration/test_baseline_agent_flow.py` -> `37 passed`
- `.venv/bin/python -m pytest -q` -> `238 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `25 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `29 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `saga/agent.py`
- `saga/common/crypto.py`
- `saga/provider/provider.py`
- `saga/user/user.py`
- `tests/security/test_otk_signature_binding.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 本轮规定测试已通过。
- 已形成本地 checkpoint：
  - commit: `cf8a863 checkpoint: bind otk signatures to aid`
- 已推送备份分支：
  - `origin/backup/repro-local` -> `cf8a863`
- 未推送到主开发分支。

### 2026-06-01 E7 Challenge Boundary Closure Session

目标：

- 完成 E7 第一阶段收口：决定 challenge 派生边界，并避免将显式 Python / SHA-256 预处理误表述为全神经化哈希。

已做工作：

- 更新 `neural/compiled_lwe_dnn.py`：
  - 新增 `CompiledVerifierBoundary`
  - 新增 `CompiledToyLWEVerifier.compilation_boundary()`
  - `ProjectionTrace` 新增 `challenge_source`
  - 将当前边界固定为：
    - fixed circuit：公开矩阵投影
    - deterministic preprocessing：字节 / 向量解码与 SHA-256 challenge 派生
    - deterministic hard gates：模减、逐坐标等式判断、全坐标接受聚合
- 更新 `neural/__init__.py`：
  - 导出 `CompiledVerifierBoundary`
- 更新 `tests/test_compiled_lwe_dnn.py`：
  - 覆盖 `challenge_source`
  - 覆盖 `compilation_boundary()`，确保 SHA-256 challenge 派生不被误归入 compiled fixed circuit
- 更新 `README.md`、`SECURITY.md`、`SAGA_PQ_CAN_DESIGN.md`：
  - 明确 `toy_compiled_research` 当前不声称 SHA-256 或 hash-to-challenge 是神经电路
  - 明确 challenge 派生是 deterministic preprocessing，随后进入固定 verifier 电路
- 更新本工作文档：
  - E7 标记为第一阶段 `已完成`
  - 当前下一步切换到 E8 路线评估或 F6 端到端集成测试补强

已验证：

- `.venv/bin/python -m pytest -q tests/test_compiled_lwe_dnn.py tests/test_fixed_circuit.py` -> `18 passed`
- `.venv/bin/python -m pytest -q` -> `223 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `README.md`
- `SAGA_PQ_CAN_DESIGN.md`
- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `neural/__init__.py`
- `neural/compiled_lwe_dnn.py`
- `tests/test_compiled_lwe_dnn.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 本次实现与文档边界收口已形成本地 checkpoint：
  - `75b48d4 checkpoint: document compiled verifier boundary`
- 首次 `git push origin HEAD:backup/repro-local` 被系统 SSH 配置权限阻塞：
  - `/etc/ssh/ssh_config.d/20-systemd-ssh-proxy.conf`
- 随后使用临时 `/tmp/saga_known_hosts` 与显式 `GIT_SSH_COMMAND` 只推送备份分支，已成功：
  - `origin/backup/repro-local`
- 未推送主开发分支。

### 2026-05-30 Paper Table Helper Session

目标：

- 固化 `2026-05-27` baseline/PQ-CAN 两个真实三任务 summary 的论文表格口径。

已做工作：

- 新增 `experiments/paper_tables.py`：
  - 默认读取 baseline summary：
    `experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json`
  - 默认读取 PQ-CAN summary：
    `experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json`
  - 输出 run-level / task-level 表格数据
  - 支持 `--format json` 与 `--format markdown`
  - API cost/token usage 继续只在 summary 显式提供时标记 available，不做价格估算
  - audit 计数只来自 execution-gate audit record，不把模型/工具 permission text 或 parsing retry 归为 PQ-CAN gate reject
- 新增 `tests/test_paper_tables.py`：
  - 覆盖 run-level 和 task-level 字段
  - 覆盖 conservative cost/token semantics
  - 覆盖 Markdown 格式化
  - 在本地 ignored summary 存在时 smoke 读取 `2026-05-27` 两个真实 summary
- 更新 `SECURITY.md`：
  - 记录 `experiments/paper_tables.py` 的用法与表格口径。
- 更新本工作文档：
  - 新增 G10 并标记为 `已完成`
  - 当前下一步切换到真实服务负向样本升级与 runtime mode split

已验证：

- `.venv/bin/python -m pytest -q tests/test_paper_tables.py` -> `5 passed`
- `.venv/bin/python experiments/paper_tables.py --format json` -> 成功输出 baseline/PQ-CAN run-level 与 task-level JSON 表格
- `.venv/bin/python experiments/paper_tables.py --format markdown` -> 成功输出 baseline/PQ-CAN Markdown 表格
- `.venv/bin/python -m pytest -q` -> `201 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/paper_tables.py`
- `tests/test_paper_tables.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次只读取 ignored `experiments/runs/` 中既有 summary，未提交运行产物。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。

### 2026-05-31 Real-Service Negative Runner Expansion Session

目标：

- 执行并扩展 opt-in 真实服务负向 runner，将离线 runtime-path 样本进一步升级到真实 Provider/token/TLS/socket/listener 路径。

已做工作：

- 先在默认沙箱内运行：
  - `.venv/bin/python experiments/real_negative_runner.py run --scenario all`
  - 失败于 `mongod` 启动阶段，`mongod.log` 显示 `set_option: Operation not permitted`，属于沙箱本地 socket 权限限制。
- 经用户授权后在沙箱外运行现有 runner：
  - `.venv/bin/python experiments/real_negative_runner.py run --scenario all`
  - 运行目录：
    `experiments/runs/20260531T121532Z-real-negative-missing_request_envelope-tampered_message/`
  - `missing_request_envelope` / `tampered_message` 均 PASS，且 `local_runs=0`。
- 扩展 `experiments/real_negative_runner.py`：
  - 默认场景从 2 个扩展为 5 个：
    - `missing_request_envelope`
    - `tampered_message`
    - `prompt_surface_tool_only`
    - `replayed_envelope`
    - `wrong_trusted_sender_key`
  - `prompt_surface_tool_only` 构造已签名 `tool_call:add_calendar_event` envelope，真实 receiver 在 prompt surface 前以 `prompt_scope_not_authorized` 拒绝。
  - `replayed_envelope` 对同一 listener 建立两次真实连接，第二次复用同一 signed envelope，真实 receiver 以 `replayed_request_envelope` 拒绝。
  - `wrong_trusted_sender_key` 在 listener 侧将 sender trusted public key 替换为 receiver 自身 toy public key，真实 receiver 以 `signature_verification_failed` 拒绝。
- 更新 `tests/test_real_negative_runner.py`：
  - 覆盖新场景清单
  - 覆盖 tool-only payload 不包含 `llm_prompt` 授权
  - 覆盖 wrong-key payload 本身保持合法签名语义，错误发生在 receiver trust map
  - 覆盖 replay 场景需要两次真实连接
  - 覆盖 listener 命令传入 `--wrong-trusted-sender-aid`
- 更新 `SECURITY.md`：
  - 将真实服务负向 runner 文档从两场景更新为五场景
  - 示例命令改为 `--scenario all`
- 更新本工作文档：
  - H13 标记为 `已完成`
  - 当前下一步改为拆清 `toy mode / compiled research mode / ML-DSA mode`

已验证：

- `.venv/bin/python -m pytest -q tests/test_real_negative_runner.py` -> `9 passed`
- `.venv/bin/python -m pytest -q tests/test_real_negative_runner.py tests/test_negative_injection_runner.py tests/test_batch_run.py` -> `24 passed`
- `.venv/bin/python experiments/real_negative_runner.py run --scenario all`（沙箱外授权运行） -> `5/5` PASS
  - 运行目录：
    `experiments/runs/20260531T122842Z-real-negative-missing_request_envelope-tampered_message-prompt_surface_tool_only-replayed_envelope-wrong_trusted_sender_key/`
  - `missing_request_envelope`: expected/observed `missing_request_envelope`, `local_runs=0`
  - `tampered_message`: expected/observed `message_digest_mismatch`, `local_runs=0`
  - `prompt_surface_tool_only`: expected/observed `prompt_scope_not_authorized`, `local_runs=0`
  - `replayed_envelope`: expected/observed `replayed_request_envelope`, `local_runs=0`
  - `wrong_trusted_sender_key`: expected/observed `signature_verification_failed`, `local_runs=0`
- `.venv/bin/python -m pytest -q` -> `210 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `experiments/real_negative_runner.py`
- `tests/test_real_negative_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 真实 runner 产物写入 ignored `experiments/runs/`，不进入提交范围。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。

### 2026-05-31 Runtime Auth Mode Split Session

目标：

- 完成 F10：拆清 `toy mode / compiled research mode / ML-DSA mode` 运行路径，避免 research-only toy wiring 与未来 ML-DSA adapter 语义混用。

已做工作：

- 更新 `saga/config.py`：
  - `ToyRuntimeAuthConfig` 新增 `mode`
  - 支持 `toy_compiled_research` / `toy_wrapper` / `mldsa_external`
  - 新增 `resolved_mode()`，旧 YAML 缺省 `mode` 时由 `verifier_flavor` 推导
  - 新增 `toy_verifier_flavor()`，仅 toy modes 可转换为 `compiled` / `wrapper`
  - 显式拒绝 `mode` 与旧 `verifier_flavor` 冲突的配置
- 更新 `saga/agent.py`：
  - `enable_toy_lwe_runtime_auth(...)` 与 `enable_toy_lwe_runtime_auth_from_config(...)` 补齐 `now_fn` / config 类型标注
  - config-driven helper 只允许 toy modes 进入 toy LWE wiring
  - `mldsa_external` 当前抛出 `RuntimeError` fail-closed，避免没有外部 vetted backend 时静默回退到 toy 签名
- 更新测试：
  - `tests/test_agent_runtime_auth.py` 覆盖显式 `toy_wrapper`、冲突 mode/flavor 拒绝、`mldsa_external` fail-closed
  - `tests/test_runtime_auth_configs.py` 覆盖 checked-in `emma_pqcan.yaml` / `raj_pqcan.yaml` 旧配置规范化为 `toy_compiled_research`
- 更新文档：
  - `README.md` 示例新增 `mode: toy_compiled_research`
  - `SECURITY.md` 记录 `toy_compiled_research` / `toy_wrapper` / `mldsa_external` 安全边界
  - 本工作文档将 F10 标记为 `已完成`，当前下一步切换到 F14

已验证：

- `.venv/bin/python -m pytest -q tests/test_agent_runtime_auth.py tests/test_runtime_auth_configs.py tests/test_execution_gate_factory.py tests/integration/test_experiment_runtime_auth_entrypoints.py` -> `20 passed, 12 subtests passed`
- `.venv/bin/python -m pytest -q` -> `213 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `24 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `README.md`
- `SECURITY.md`
- `saga/agent.py`
- `saga/config.py`
- `tests/test_agent_runtime_auth.py`
- `tests/test_runtime_auth_configs.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。

### 2026-05-31 Requested Scope Envelope Proof Session

目标：

- 完成 F14：证明 LLM / runtime requested scopes 只能作为 proposal，不能扩大 signed request envelope 中的授权范围。

已做工作：

- 更新 `tests/integration/test_baseline_agent_flow.py`：
  - 新增 `test_requested_scope_escalation_does_not_expand_signed_envelope`
  - 构造带本地工具 policy 的真实 `Agent` shell
  - 传入越权 requested scopes：
    - `tool_call:send_email`（允许）
    - `tool_call:add_calendar_event`（未暴露工具，拒绝）
    - `delegation`（拒绝）
  - 断言 `Agent._conversation_policy_decision(...)` 返回 `scope_escalation`
  - 断言 signed envelope 的 `authorized_scopes` 只包含：
    - `llm_prompt`
    - `memory_read`
    - `memory_write`
    - `tool_call:send_email`
  - 断言 rejected scopes 不出现在 signed envelope 中
  - 通过 `SignedRequestExecutionGate` 构造 `LocalExecutionContext`，确认 downstream context 只授权 `send_email`，不授权 `add_calendar_event` 或 `delegation`
- 更新 `SECURITY.md`：
  - 明确 rejected requested scopes 不得进入 signed request envelope 的 `authorized_scopes`
  - downstream `LocalExecutionContext` 只能授予通过本地 policy 编译并完成签名验签的 scopes
- 更新本工作文档：
  - F14 标记为 `已完成`
  - 当前下一步切换到 F3 / F7 授权公式收口

已验证：

- `.venv/bin/python -m pytest -q tests/test_intent.py tests/integration/test_baseline_agent_flow.py tests/test_negative_injection_runner.py` -> `31 passed`
- `.venv/bin/python -m pytest -q` -> `214 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `25 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `tests/integration/test_baseline_agent_flow.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。

### 2026-05-31 F3/F7 Authorization Formula Closure Session

目标：

- 完成 F3/F7：把最终授权公式从文档约束收口到 decision、audit 和 Agent runtime 测试中。

已做工作：

- 更新 `saga/execution_gate.py`：
  - `ExecutionGateDecision` 新增六项公式字段：
    - `protocol_allow`
    - `request_envelope_valid`
    - `pq_signature_valid`
    - `can_accept`
    - `execution_scope_allowed`
    - `internal_policy_accept`
  - 新增 `formula_terms()` 与 `with_formula_values(...)`
  - execution-gate audit record 新增 `authorization_formula`
  - `SignedRequestExecutionGate.evaluate_request(...)` 在成功、签名/CAN 失败和 scope 检查路径中填充公式项
- 更新 `saga/agent.py`：
  - token 通过后将 `saga_token_valid=True` 合入 gate decision
  - prompt surface 检查继承 token/envelope/signature/CAN 公式项
  - prompt scope 缺失时记录 `execution_scope_allowed=False` 与 `internal_policy_accept=False`
  - `_conversation_policy_decision(...)` 不再自动把任意入口 `action_scope` 纳入本地 policy
  - `_conversation_authorized_scopes(...)` 遇到 `policy_reject` 会 fail-closed 抛 `ExecutionAuthorizationError`
  - 非 prompt 的 `tool_call:*` 入口默认不再携带 `llm_prompt`
- 更新测试：
  - `tests/test_execution_gate.py` 覆盖 valid decision 公式项、签名失败公式项和 audit 中的 `authorization_formula`
  - `tests/integration/test_baseline_agent_flow.py` 覆盖真实 receiving-side audit 公式项、prompt surface 拒绝公式项、入口 policy reject 和 tool entry 不隐式授权 prompt
  - `tests/test_real_negative_runner.py` 调整 tool-only 构造测试，使样本代表“工具入口已被本地 policy 允许但不能进入 prompt surface”
- 更新 `SECURITY.md`：
  - 最终公式改为六项
  - 记录 audit 中的 `authorization_formula`
  - 记录入口 policy reject 在信封构造前 fail-closed，工具入口不隐式授权 prompt
- 更新本工作文档：
  - F3 / F7 标记为 `已完成`
  - 当前下一步切换到 E10 / E7

已验证：

- `.venv/bin/python -m pytest -q tests/test_execution_gate.py tests/integration/test_baseline_agent_flow.py tests/test_intent.py tests/test_real_negative_runner.py tests/test_negative_injection_runner.py` -> `68 passed`
- `.venv/bin/python -m pytest -q` -> `217 passed, 21 subtests passed`
- `.venv/bin/python -m pytest -q tests/security` -> `18 passed`
- `.venv/bin/python -m pytest -q tests/integration` -> `28 passed, 12 subtests passed`
- 未发现 `ruff` / `mypy` 配置文件，因此未运行 `ruff check .` 或 `mypy .`。

当前 checkpoint 待提交文件范围：

- `SAGA_PQ_CAN_WORKLOG.md`
- `SECURITY.md`
- `saga/agent.py`
- `saga/execution_gate.py`
- `tests/integration/test_baseline_agent_flow.py`
- `tests/test_execution_gate.py`
- `tests/test_real_negative_runner.py`

敏感文件审查：

- 待提交文件不包含 secrets、生成凭据、本地 DB、模型 checkpoint、实验运行结果或 `paper/`。
- 本次未启动真实服务 runner 或模型 batch，未生成新的实验运行产物。

GitHub / checkpoint 状态：

- 当前工作区改动尚未形成 checkpoint commit；需在规定测试通过后执行最终 git 状态检查。
