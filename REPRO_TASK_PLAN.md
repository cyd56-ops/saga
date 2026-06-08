# SAGA 复现实施任务单

本文档把 [REPRO_GAP_CHECKLIST.md](/home/kali/saga/REPRO_GAP_CHECKLIST.md:1) 里的缺口展开成可执行任务，按优先级、涉及文件、预期交付物、验收标准整理。

目标范围：

- 以当前仓库为基底，补齐论文主线系统复现缺口。
- 不处理论文作者自己提出但不属于主线必需的扩展设计，例如 `RAFT / Paxos / PBFT / sharding / fault-tolerance / capacity`。

---

## Phase 1：先修核心正确性

这些任务优先级最高，因为它们直接影响协议是否按论文语义正确工作。

### T1. 修复 contact policy “最具体规则优先” 语义

目标：

- 让 contact rulebook 的匹配行为与论文一致。
- 多条规则命中时，严格选择“最具体”的规则。

涉及文件：

- [saga/common/contact_policy.py](/home/kali/saga/saga/common/contact_policy.py:137)

需要修改：

- 修 `match()` 中 `best_pattern` 未更新的问题。
- 明确当多个模式 specificity 相同的时候如何决策：
  - 方案 A：保持首个匹配优先
  - 方案 B：保持后者覆盖前者
- 把 tie-break 规则写进注释和文档，避免行为不透明。

建议补充：

- 为 `check_rulebook()`、`aid_specificity()`、`match()` 增加单元测试。
- 覆盖：
  - `*`
  - `*@company.com:*`
  - `alice@company.com:calendar_agent`
  - blocklist `budget = -1`
  - 无命中

验收标准：

- 同一组规则对同一 AID 的预算结果可预测、可测试、与论文语义一致。

---

### T2. 修复 token cache / lock 的死锁风险

目标：

- 去掉 token 复用路径中的已知死锁点。
- 保持 token 有效性检查与失效清理的线程安全。

涉及文件：

- [saga/agent.py](/home/kali/saga/saga/agent.py:383)
- [saga/attack_models/adversaries/A1.py](/home/kali/saga/saga/attack_models/adversaries/A1.py:383)
- [saga/attack_models/adversaries/A2.py](/home/kali/saga/saga/attack_models/adversaries/A2.py:383)
- [saga/attack_models/adversaries/A3.py](/home/kali/saga/saga/attack_models/adversaries/A3.py:383)
- [saga/attack_models/adversaries/A4.py](/home/kali/saga/saga/attack_models/adversaries/A4.py:383)
- [saga/attack_models/adversaries/A5.py](/home/kali/saga/saga/attack_models/adversaries/A5.py:383)
- [saga/attack_models/adversaries/A6.py](/home/kali/saga/saga/attack_models/adversaries/A6.py:383)
- [saga/attack_models/adversaries/A8.py](/home/kali/saga/saga/attack_models/adversaries/A8.py:388)
- [saga/attack_models/benign/A5.py](/home/kali/saga/saga/attack_models/benign/A5.py:387)

需要修改：

- 重构 `retrieve_valid_token()` 与 `received_token_is_valid()` 的锁使用方式。
- 避免“持锁调用另一个也会尝试获取同一把锁的函数”。

建议实现方式：

- 方案 A：将 `received_token_is_valid()` 改为内部私有无锁版本 + 外部加锁包装。
- 方案 B：统一在 `retrieve_valid_token()` 内完成读取、判断、清理，不再嵌套调用。

验收标准：

- token 复用路径在多线程 listen/connect 场景下不会自锁。
- 主实现与攻击模型实现保持一致行为。

---

### T3. 清理残留 `lookup()` 路径，避免协议入口混乱

目标：

- 明确当前协议只通过 `/access` 获取目标 agent 信息与 OTK。
- 移除或实现 `lookup()`，避免半成品接口留在主代码路径中。

涉及文件：

- [saga/agent.py](/home/kali/saga/saga/agent.py:256)
- 对应攻击模型中的 `lookup()` 残留实现

建议决策：

- 如果论文主线不再需要 `/lookup`：
  - 删除 `lookup()` 及相关注释
  - 更新文档避免误导
- 如果希望保留“纯查询 metadata”能力：
  - 需在 Provider 中正式实现 `/lookup`
  - 明确它与 `/access` 的权限和返回值差异

验收标准：

- 代码中不存在“调用不存在接口”的主路径逻辑。

---

## Phase 2：补齐 agent lifecycle management

这是论文第 IV-D 的主线能力，不补则不能算完整复现论文主线系统。

### T4. Contact policy update

状态：

- 已存在，需要补测试与语义确认

目标：

- 验证用户能动态更新某个 agent 的 contact policy，且语义符合论文主线。

涉及文件：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:88)
- [saga/user/user.py](/home/kali/saga/saga/user/user.py:152)
- [saga/config.py](/home/kali/saga/saga/config.py:94)

当前实现：

- Provider 端已有 `POST /update_policy`
- User 端已有 `update_policy()`

Next:

- 验证只有 owner 可更新；
- 验证 blocklist 更新后立即影响 `/access`；
- 验证旧 token 是否继续有效，并在文档中说明语义；
- 验证 rulebook 格式错误时 fail closed。

验收标准：

- 更新后新的访问请求立即按新策略生效。
- blocklist 规则可实时阻止新 access 请求。

---

### T5. Agent deactivation

状态：

- 已存在，需要补测试与语义确认

目标：

- 验证用户可停用自己的 agent，使其他 agent 无法继续通过 Provider 获取其访问材料。

涉及文件：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:88)
- [saga/user/user.py](/home/kali/saga/saga/user/user.py:152)

当前实现：

- Provider 端已有 `POST /deactivate_agent`
- 数据模型已使用 `active` / `deactivated_at`

Next:

- 验证只有 owner 可停用；
- 验证停用后 `/access` 会拒绝新请求；
- 验证重复停用返回一致且可解释的失败语义。

验收标准：

- 已停用 agent 无法被新的 initiating agent 发现并建立新 token。
- 只允许 owner 停用自己的 agent。

---

### T6. OTK refresh

状态：

- 已存在，需要补测试与语义确认

目标：

- 验证用户可为已注册 agent 追加或刷新 OTK，满足论文中的 key refresh / replenishment 需求。

涉及文件：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:88)
- [saga/user/user.py](/home/kali/saga/saga/user/user.py:152)

当前实现：

- Provider 端已有 `POST /refresh_otks`
- User 端已有 `refresh_otks()`
- 当前语义为“追加”而不是“整体替换”

Next:

- 验证签名校验正确生效；
- 验证重复 OTK 会被拒绝；
- 验证 OTK pool 耗尽后可通过 refresh 恢复；
- 验证只有 owner 可刷新。

验收标准：

- OTK 池耗尽后，用户可刷新，后续 `/access` 能继续正常返回 OTK。

---

## Phase 3：补齐协议忠实度

这些任务不一定阻塞 demo，但能提高与论文协议的对齐程度。

### T7. 让 OTK 签名绑定 `aid`

目标：

- 将 OTK 的签名语义从“只签 OTK bytes”改为“签 `aid + OTK`”。

涉及文件：

- [saga/user/user.py](/home/kali/saga/saga/user/user.py:247)
- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:320)
- [saga/agent.py](/home/kali/saga/saga/agent.py:816)

需要修改：

- 用户注册 agent 时的 OTK 签名内容
- Provider 注册时的校验逻辑
- Initiating agent 使用 OTK 前的校验逻辑

兼容性注意：

- 这会影响已有 `agent.json` 和数据库中已注册数据。
- 需要决定是否：
  - 重新注册所有测试用户/agent
  - 或支持旧格式兼容迁移

验收标准：

- OTK 签名内容与论文协议一致。

---

### T8. 把 token lifetime / quota 配置化

目标：

- 不再硬编码 `1 hour` 和 `Q_MAX = 50`。

涉及文件：

- [saga/agent.py](/home/kali/saga/saga/agent.py:295)
- [saga/config.py](/home/kali/saga/saga/config.py:74)
- [user_configs/*.yaml](/home/kali/saga/user_configs/emma.yaml:1)

建议设计：

- 全局默认值：
  - `token_lifetime_minutes`
  - `token_quota`
- 支持 agent 级覆盖

建议修改点：

- `saga/config.py` 增加配置读取
- `generate_token()` 从配置读取 lifetime / quota

验收标准：

- 不改代码即可通过配置改变 token lifetime 和 request quota。

---

### T9. 明确 user registration 的身份验证语义

目标：

- 至少在代码和文档层面说清楚：当前实现是简化版本地认证，而不是完整 OIDC / human verification。

涉及文件：

- [README.md](/home/kali/saga/README.md:1)
- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:34)

可选方向：

- 最小方案：
  - 文档中明确“当前实现是简化版 identity/auth”
- 扩展方案：
  - 真正接入 OIDC / external verification stub

验收标准：

- 仓库表达与实际实现一致，不误导复现结论。

---

## Phase 4：补齐实验复现能力

目标不是只把 demo 跑通，而是尽量让论文主线实验可重复执行、可验收。

### T10. 统一三类任务实验的执行入口

目标：

- 给 `schedule_meeting.py`、`expense_report.py`、`create_blogpost.py` 增加统一调度入口。

建议新增文件：

- `experiments/run_task.py`
- 或 `experiments/run_all_tasks.py`

建议功能：

- 指定任务名
- 指定发起方/接收方 config
- 自动输出 success/failure 与耗时

验收标准：

- 可以通过统一命令运行任一论文任务。

---

### T11. 强化 Calendar 任务验收

目标：

- 让会议任务的 success 判定更贴近论文描述。

涉及文件：

- [experiments/schedule_meeting.py](/home/kali/saga/experiments/schedule_meeting.py:18)
- [agent_backend/tools/calendar.py](/home/kali/saga/agent_backend/tools/calendar.py:1)

建议补充校验：

- 参会者必须仅为目标双方
- 事件时长严格符合期望
- 双方日历中 event 内容一致
- 不与原有事件冲突

验收标准：

- success 不再仅表示“生成了某个 meeting”，而是表示“meeting 正确”。

---

### T12. 强化 Blogpost 任务验收

目标：

- 让 blogpost 任务不止检查“文件存在”。

涉及文件：

- [experiments/create_blogpost.py](/home/kali/saga/experiments/create_blogpost.py:17)
- [agent_backend/tools/documents.py](/home/kali/saga/agent_backend/tools/documents.py:1)

建议补充校验：

- 文件名严格匹配预期
- 内容非空且长度超过阈值
- 包含主题关键词
- 若论文要求 credit，则检查署名信息

验收标准：

- success 能较好代表任务真正完成。

---

### T13. 把 overhead 采集整理成实验产物

目标：

- 把已有 `Monitor` 输出转成可保存、可汇总的数据。

涉及文件：

- [saga/common/overhead.py](/home/kali/saga/saga/common/overhead.py:1)
- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:86)
- [saga/agent.py](/home/kali/saga/saga/agent.py:236)

建议新增：

- 统一结果输出目录，例如 `experiments/results/`
- 保存：
  - `provider:access`
  - `agent:token_init`
  - `agent:token_recv`
  - `agent:communication_proto_*`
  - `agent:llm_backend_*`

验收标准：

- 单次任务执行后能拿到结构化 overhead 数据，而不是仅 stdout 日志。

---

## Phase 5：补齐攻击与验证复现入口

### T14. 给攻击场景加自动断言

目标：

- 把攻击 demo 变成可批量回归的测试场景。

涉及文件：

- [experiments/adversary.py](/home/kali/saga/experiments/adversary.py:36)
- [experiments/README.md](/home/kali/saga/experiments/README.md:1)

建议方式：

- 为每个攻击场景定义：
  - 预期结果
  - 判定条件
  - 是否成功防御
- 输出统一摘要：
  - `attack_id`
  - `expected`
  - `observed`
  - `pass/fail`

验收标准：

- A1/A2/A3/A4/A5/A6/A8 可批量执行并给出机器可读结果。

---

### T15. 给形式化验证补统一执行入口

目标：

- 让 `proofs` 目录不只是手工说明，而是可一键执行。

涉及文件：

- [proofs/README.md](/home/kali/saga/proofs/README.md:1)
- [proofs/flake.nix](/home/kali/saga/proofs/flake.nix:1)

建议新增：

- `proofs/run_proofs.sh`
- 或 `Makefile`

建议功能：

- 跑 `proverif/registration.pv`
- 跑 `proverif/agent_communication.pv`
- 可选跑 `verifpal/*`
- 保存 stdout/stderr 到结果文件

验收标准：

- 可一键得到形式化验证结果归档。

---

## 推荐执行顺序

### Sprint 1：修核心协议正确性

1. T1 修 contact policy specificity
2. T2 修 token lock / deadlock
3. T3 清理 lookup 残留

### Sprint 2：补 lifecycle management

4. T4 policy update
5. T5 agent deactivation
6. T6 OTK refresh

### Sprint 3：补协议忠实度

7. T7 OTK 签名绑定 aid
8. T8 token 参数配置化
9. T9 身份验证语义澄清

### Sprint 4：补实验复现能力

10. T10 统一任务运行入口
11. T11 强化 calendar 验收
12. T12 强化 blogpost 验收
13. T13 结构化 overhead 采集

### Sprint 5：补攻击与证明复现入口

14. T14 攻击批量断言
15. T15 proofs 一键执行

---

## 最小可交付版本

如果目标是尽快达到“可以比较严肃地声称复现了论文主线系统”，最小建议集合是：

- T1
- T2
- T4
- T5
- T6
- T8
- T10
- T11
- T13
- T14
- T15

---

## 当前建议

下一步最合适的是直接进入 `Sprint 1`，先修：

1. `contact_policy.py`
2. `agent.py`
3. 攻击模型中与 token cache 相关的并行实现

这三项修完后，再补 lifecycle management，整体返工最少。
