# SAGA-PQ-CAN API 真实测试栈测试设计方案（当前仓库真实可执行版）

## 0. 文档定位

本文档是面向**当前仓库现状**的真实测试修订稿。

目标不是写“理想设计方案”，而是明确：

1. 哪些真实测试现在就能执行；
2. 哪些判断现在就能落地；
3. 哪些增强测试还不能直接做；
4. 第一轮真实测试应如何避免误判。

本稿后续将作为真实测试工作的执行基线。

---

## 1. 本版结论

按当前仓库状态，可以立即开展的真实测试范围为：

1. `SAGA baseline` 三个正向任务；
2. `SAGA + PQ-CAN runtime auth` 三个正向任务；
3. 两个最小负向场景：
   - 缺失签名材料；
   - receiver trusted public key 不匹配。

当前**不应**把以下内容当成“已可执行”：

1. `tampered_envelope`；
2. `message_digest_mismatch`；
3. `unauthorized_tool_scope`；
4. `expired_envelope`；
5. `wrong_receiver_aid`；
6. 负向场景自动注入批跑脚本；
7. `local_agent_run_called` / `tool_calls_executed` 级别的自动观测。

---

## 2. 当前代码事实

当前仓库已具备以下真实测试支撑：

1. 真实实验入口存在：
   - `experiments/schedule_meeting.py`
   - `experiments/expense_report.py`
   - `experiments/create_blogpost.py`

2. 真实 OpenAI API 配置路径已接入：
   - `agent_backend/base.py`
   - `agent_backend/config.py`

3. runtime auth 会从 `*_pqcan.yaml` 自动启用：
   - `enable_toy_lwe_runtime_auth_from_config(...)`

4. 会话消息已携带：
   - `action_scope`
   - `request_envelope`
   - `pq_signature`

5. 接收侧 gate 已支持拒绝以下最小负向原因：
   - `missing_request_envelope`
   - `missing_pq_signature`
   - `untrusted_sender_aid`
   - `signature_verification_failed`
   - 以及若干 envelope 一致性错误

6. 接收侧拒绝时会写本地审计：
   - `user/<aid>/audit/execution_gate.jsonl`

7. 实验结果会写 JSONL：
   - `experiments/results/*.jsonl`

---

## 3. 当前版测试范围

### 3.1 包含

1. 真实 OpenAI API 调用；
2. 真实 `smolagents` wrapper；
3. 真实本地工具：
   - calendar
   - email
   - documents
4. 真实 SAGA CA / Provider / User / Agent 链路；
5. `*_pqcan.yaml` 驱动的 toy runtime auth；
6. receiver 侧 execution gate 审计；
7. 三个任务的真实端到端可达性验证；
8. 最小负向 fail-closed 验证。
9. 第一版正向任务批跑入口：
   - `experiments/batch_run.py`
   - 支持连续模型探针稳定后再启动本地服务、seed 数据和 listen/query 任务。

### 3.2 不包含

1. 论文级性能复现；
2. 大规模并发；
3. 生产级 PQ 签名后端；
4. 篡改类负向自动注入；
5. tool 级 unauthorized scope 自动攻击脚本；
6. 负向场景自动化批跑；
7. 发送侧/接收侧全链路调用埋点统计。

---

## 4. 当前版可执行测试矩阵

### 4.1 Baseline 正向

| 任务 | 发起方配置 | 接收方配置 | 预期 |
|---|---|---|---|
| Meeting | `emma.yaml` | `raj.yaml` | 成功 |
| Expense | `emma.yaml` | `raj.yaml` | 成功 |
| Blogpost | `emma.yaml` | `raj.yaml` | 成功 |

### 4.2 PQ-CAN 正向

| 任务 | 发起方配置 | 接收方配置 | 预期 |
|---|---|---|---|
| Meeting | `emma_pqcan.yaml` | `raj_pqcan.yaml` | 成功 |
| Expense | `emma_pqcan.yaml` | `raj_pqcan.yaml` | 成功 |
| Blogpost | `emma_pqcan.yaml` | `raj_pqcan.yaml` | 成功 |

### 4.3 最小负向

| 场景 | 发起方配置 | 接收方配置 | 预期 |
|---|---|---|---|
| 缺失签名材料 | `emma.yaml` | `raj_pqcan.yaml` | receiver 拒绝 |
| trusted public key 不匹配 | `emma_pqcan.yaml` | `raj_pqcan_bad_trust.yaml` | receiver 拒绝 |

---

## 5. 当前版判定原则

### 5.1 正向任务成功判定

正向场景至少同时满足：

1. query 端最终输出 `Success: True`；
2. 对应任务 JSONL 中存在 `mode=query` 的结果记录；
3. 该记录中的 `success = true`；
4. 若为 PQ-CAN 正向，receiver 侧不应出现与本次运行对应的 reject 审计。

### 5.2 负向任务成功判定

当前仓库没有 `local_agent_run_called`、`tool_calls_executed` 等字段，因此**本版不得**用这些字段作为通过条件。

当前负向场景采用以下可落地证据：

1. query 侧任务最终未成功；
2. receiver 侧 `execution_gate.jsonl` 出现拒绝记录；
3. 拒绝 reason 与场景匹配；
4. 未观察到预期业务副作用：
   - meeting：未新增符合任务意图的会议；
   - expense：HR 未收到新的有效报销邮件；
   - blogpost：未新增符合任务意图的新文档。

### 5.3 结果文件使用规则

当前实验脚本在 `listen` 和 `query` 两侧都会写结果行。

因此统计时必须遵守：

1. 成功率统计只看 `mode=query`；
2. `mode=listen` 记录只用于辅助排障；
3. 不要把同一轮 listen/query 两条记录当成两次任务执行。

### 5.4 审计文件使用规则

当前实验脚本 query 侧写入的 `audit_reject_count` 来自**发起方 workdir**，不能替代 receiver 侧真实 gate 审计。

因此负向场景必须直接查看 receiver workdir 下的：

```text
user/<receiver_aid>/audit/execution_gate.jsonl
```

---

## 6. 前置条件

1. 使用 repo-local Python：

```bash
.venv/bin/python
```

2. 依赖已安装：

```bash
.venv/bin/python -m pip install -e .
```

3. 本地 MongoDB 可用：

```text
mongodb://127.0.0.1:27017/saga_tools
```

4. `config.yaml` 应指向本机 CA / Provider endpoint。

推荐：

```bash
cp config_local.yaml config.yaml
```

5. 已设置：

```bash
export OPENAI_API_KEY="<YOUR_OPENAI_API_KEY>"
```

6. 端口可用：

```text
CA: 8000
Provider: 5000
Emma agents: 7000-7002
Raj agents: 7003-7005
```

7. 以下配置文件存在且可解析：

```text
user_configs/emma.yaml
user_configs/raj.yaml
user_configs/emma_pqcan.yaml
user_configs/raj_pqcan.yaml
```

---

## 7. 风险与限制

### 7.1 API 与模型风险

1. 真实 API 响应非确定；
2. 可能受限流、余额、网络波动影响；
3. 单次成功或失败都不能直接下强结论。

### 7.2 任务 oracle 限制

1. `schedule_meeting.py` 的判定仍偏弱；
2. `create_blogpost.py` 主要检查文件存在和标题匹配；
3. `expense_report.py` 主要检查 HR 收件与金额字符串，不是严格语义验收。

### 7.3 runtime auth 限制

1. 当前是 toy runtime auth，仅限 research；
2. 不代表 production PQ security；
3. 当前 action scope 在实验入口里并未开放成可随意注入的测试参数。

### 7.4 观测限制

当前仓库没有现成字段可以自动证明：

1. `local_agent.run()` 一定未调用；
2. 所有 tool executor 一定未调用；
3. 调用次数为 0。

因此本版采用“receiver 审计 + 无业务副作用”的组合证据。

---

## 8. 注册与环境准备规则

### 8.1 环境准备

```bash
cp config_local.yaml config.yaml
.venv/bin/python -m pip install -e .
```

按本机实际方式启动 MongoDB。

### 8.2 生成 CA 凭据

```bash
.venv/bin/python generate_credentials.py ca saga/ca/
```

### 8.3 启动 CA 文件服务

终端 1：

```bash
cd /home/kali/saga/saga/ca
/home/kali/saga/.venv/bin/python -m http.server 8000
```

### 8.4 启动 Provider

终端 2：

```bash
cd /home/kali/saga/saga/provider
../../.venv/bin/python provider.py
```

### 8.5 注册用户与 agent

首次环境可执行：

```bash
cd /home/kali/saga/saga/user
../../.venv/bin/python user.py --register --register-agents --uconfig ../../user_configs/emma.yaml
../../.venv/bin/python user.py --register --register-agents --uconfig ../../user_configs/raj.yaml
```

### 8.6 PQ-CAN 配置注册规则

`emma_pqcan.yaml` / `raj_pqcan.yaml` 与 baseline 配置复用了相同邮箱、agent 名与端口。

因此当前版规则是：

1. 默认**不要**再次执行 `--register --register-agents` 来单独注册 PQ-CAN 配置；
2. PQ-CAN 测试应优先复用同一套已注册 agent 材料；
3. PQ-CAN 与 baseline 的区别主要体现在运行时是否启用 `toy_runtime_auth`；
4. 若必须重建环境，应先清理旧状态后再统一重注册，不要混合重复注册。

### 8.7 重置工具数据

```bash
cd /home/kali/saga/experiments
../.venv/bin/python seed_tool_data.py ../user_configs
```

建议每轮正式测试前执行一次。

---

## 9. 正向真实测试步骤

每个任务使用两个进程：

1. 一个进程运行 `listen`；
2. 一个进程运行 `query`。

### 9.1 Meeting baseline

终端 A：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py listen ../user_configs/raj.yaml
```

终端 B：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py query ../user_configs/emma.yaml ../user_configs/raj.yaml
```

### 9.2 Expense baseline

终端 A：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python expense_report.py listen ../user_configs/raj.yaml
```

终端 B：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python expense_report.py query ../user_configs/emma.yaml ../user_configs/raj.yaml
```

### 9.3 Blogpost baseline

终端 A：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python create_blogpost.py listen ../user_configs/raj.yaml
```

终端 B：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python create_blogpost.py query ../user_configs/emma.yaml ../user_configs/raj.yaml
```

### 9.4 PQ-CAN 正向

仅替换为 `*_pqcan.yaml`：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py listen ../user_configs/raj_pqcan.yaml
../.venv/bin/python schedule_meeting.py query ../user_configs/emma_pqcan.yaml ../user_configs/raj_pqcan.yaml
```

```bash
cd /home/kali/saga/experiments
../.venv/bin/python expense_report.py listen ../user_configs/raj_pqcan.yaml
../.venv/bin/python expense_report.py query ../user_configs/emma_pqcan.yaml ../user_configs/raj_pqcan.yaml
```

```bash
cd /home/kali/saga/experiments
../.venv/bin/python create_blogpost.py listen ../user_configs/raj_pqcan.yaml
../.venv/bin/python create_blogpost.py query ../user_configs/emma_pqcan.yaml ../user_configs/raj_pqcan.yaml
```

---

## 10. 最小负向测试步骤

### 10.1 缺失签名材料

目的：

验证 receiver 开启 PQ-CAN 后，baseline sender 发来的未签名请求会被拒绝。

终端 A：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py listen ../user_configs/raj_pqcan.yaml
```

终端 B：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py query ../user_configs/emma.yaml ../user_configs/raj_pqcan.yaml
```

当前版检查点：

1. query 不应得到有效成功结果；
2. receiver 侧 audit 出现拒绝；
3. reason 应与以下之一匹配：
   - `missing_request_envelope`
   - `missing_pq_signature`
4. 不应出现对应业务副作用。

### 10.2 trusted public key 不匹配

目的：

验证 sender 虽然签名，但 receiver 使用错误 trusted public key 时会拒绝。

先创建错误 trust 配置：

```bash
cp user_configs/raj_pqcan.yaml user_configs/raj_pqcan_bad_trust.yaml
```

然后只修改 receiver 侧配置中对 Emma 对应 AID 的 `trusted_public_keys` 值。

终端 A：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py listen ../user_configs/raj_pqcan_bad_trust.yaml
```

终端 B：

```bash
cd /home/kali/saga/experiments
../.venv/bin/python schedule_meeting.py query ../user_configs/emma_pqcan.yaml ../user_configs/raj_pqcan_bad_trust.yaml
```

当前版检查点：

1. query 不应得到有效成功结果；
2. receiver 侧 audit 出现拒绝；
3. reason 应与以下之一匹配：
   - `signature_verification_failed`
   - `untrusted_sender_aid`
4. 不应出现对应业务副作用。

---

## 11. 当前版结果采集方法

### 11.1 结果文件

查看：

```bash
ls -l /home/kali/saga/experiments/results
```

查看具体记录：

```bash
cat /home/kali/saga/experiments/results/schedule_meeting.jsonl
cat /home/kali/saga/experiments/results/expense_report.jsonl
cat /home/kali/saga/experiments/results/create_blogpost.jsonl
```

当前版重点字段：

1. `task_name`
2. `mode`
3. `config_path`
4. `other_config_path`
5. `agent_aid`
6. `peer_aid`
7. `runtime_auth_enabled`
8. `success`
9. `audit_reject_count`
10. `audit_reject_reasons`

### 11.2 Gate 审计

查看：

```bash
find /home/kali/saga/saga/user -path "*/audit/execution_gate.jsonl" -print
```

查看 receiver 侧审计：

```bash
cat "/home/kali/saga/saga/user/raj.sharma@gmail.com:calendar_agent/audit/execution_gate.jsonl"
```

当前版重点字段：

1. `allowed`
2. `reason`
3. `sender_aid`
4. `receiver_aid`
5. `action_scope`
6. `token_digest`
7. `recorded_at`

注意：

当前 audit 记录默认不保证带 `message_digest` 字段，因此不要把它写成必有字段。

---

## 12. 当前版通过标准

### 12.1 Batch 1：冒烟

建议执行：

1. baseline 三个任务各 1 次；
2. PQ-CAN 正向三个任务各 1 次；
3. 缺失签名负向 1 次；
4. bad trusted key 负向 1 次。

冒烟通过条件：

1. baseline 3 个任务均至少 1 次成功；
2. PQ-CAN 正向 3 个任务均至少 1 次成功；
3. 两个最小负向场景均出现 receiver 侧拒绝审计；
4. 正向场景有结果落盘；
5. 负向场景未观察到对应业务副作用。

### 12.2 Batch 2：小样本稳定性

建议在 Batch 1 通过后再执行。

建议执行：

1. baseline 每任务 3 次；
2. PQ-CAN 正向每任务 3 次；
3. 两个最小负向每场景 3 次。

当前版稳定性通过条件：

1. baseline 每任务成功率 `>= 2/3`；
2. PQ-CAN 正向每任务成功率 `>= 2/3`；
3. 两个最小负向每场景拒绝率 `= 3/3`；
4. 所有统计仅基于 `mode=query` 记录；
5. 每次负向拒绝都能在 receiver 侧找到审计证据。

---

## 13. 暂不纳入当前版的增强测试

以下场景暂不纳入正式执行清单：

1. `tampered_envelope`
2. `message_digest_mismatch`
3. `unauthorized_tool_scope`
4. `expired_envelope`
5. `wrong_receiver_aid`

原因不是这些场景不重要，而是当前实验入口尚未提供稳定注入点或自动化 harness。

这些场景应在以下前置能力补齐后再恢复：

1. 篡改型测试 harness；
2. 更强的 sender/receiver 双边结果关联；
3. `local_agent.run` 与 tool 调用埋点；
4. 更严格 task oracle。

---

## 14. 可选 proof-hardening 验收

该检查不属于默认快速 pytest 矩阵，因为它会复制临时 workspace 并按 mutation 逐项运行 pytest。
需要整理论文级 strict runtime-auth 证据或可选 CI artifact 时运行：

```bash
.venv/bin/python experiments/proof_hardening_check.py
```

该入口会执行：

1. focused proof tests；
2. `experiments/mutation_evidence_runner.py --mutation all`；
3. mutation artifact validation。

快速只跑 proof tests 可使用：

```bash
.venv/bin/python experiments/proof_hardening_check.py --skip-mutations
```

输出默认写入 ignored `experiments/runs/`，其中包含 `proof_hardening_check_summary.json`。

仓库还提供手动 GitHub Actions 入口：

```text
.github/workflows/proof-hardening.yml
```

该 workflow 只通过 `workflow_dispatch` 触发，不挂到默认 `push` / `pull_request` 快速路径。默认运行完整 proof-hardening 检查；需要快速检查时可将 `skip_mutations` 输入设为 `true`。

---

## 15. 当前版建议下一步

真实测试工作从本稿开始，执行顺序建议为：

1. 先完成 Batch 1 冒烟；
2. 若冒烟通过，再做 Batch 2 小样本稳定性；
3. 若稳定，再补以下工程能力：
   - `check_real_stack_config.py`
   - receiver 侧自动审计聚合
   - 更强结果字段
   - 增强负向测试 harness
4. 最后再进入 timing / overhead / 成本统计。

---

## 16. 最终说明

本修订稿刻意收紧到“当前仓库真实可执行”。

因此它回答的不是：

```text
系统理想上应该如何被完整验证
```

而是：

```text
今天这个仓库，哪些真实测试现在就能做，且结论不会因为观测能力不足而失真
```

后续真实测试工作以本稿为准。
