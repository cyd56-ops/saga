# SAGA 复现缺口清单

> Status: Historical gap analysis.
> Some items are outdated. Current source of truth is `SAGA_PQ_CAN_WORKLOG.md` section 3.
> Items marked as implemented-but-needs-verification should not be reimplemented blindly.
>
> 状态：历史缺口分析。
> 部分条目已过时。当前代码事实以 `SAGA_PQ_CAN_WORKLOG.md` 第 3 节为准。
> 标记为“已存在但需验证”的条目不应被重复实现。

本文档按论文主线章节整理当前仓库相对论文的复现缺口，并按优先级分为 `必须补`、`建议补`、`可忽略` 三档。

范围说明：

- 不纳入缺口：论文作者自己提出但不属于主线系统必需的扩展设计，例如 `RAFT / Paxos / PBFT / sharding / fault-tolerance / capacity`。
- 纳入对照：论文第 III、IV、VI 节，以及附录里用于支撑主张的 `形式化验证`、`攻击复现`、`3 个任务实验`。
- `A2A` 集成单独列出；若只关注 SAGA 主线，可视为建议项。

## 必须补

### 1. IV-D Agent Management：策略更新、停用 agent、刷新 OTK 已存在，需要验证与测试确认

论文明确要求：

- contact policy 可动态更新
- user 可停用自己的 agent
- user 可补充/刷新 one-time keys

当前仓库代码已经存在：

- `/register`
- `/login`
- `/register_agent`
- `/update_policy`
- `/deactivate_agent`
- `/refresh_otks`
- `/access`

当前缺口不再是“新增接口”，而是“验证这些生命周期接口是否满足论文语义并有测试覆盖”：

- `policy update`：已存在，需要测试确认 owner-only、格式校验、更新后 `/access` 立即生效；
- `deactivate agent`：已存在，需要测试确认停用后 `/access` 拒绝，且只有 owner 可停用；
- `refresh OTK`：已存在，需要测试确认签名验证、去重、OTK pool 耗尽后可恢复。

相关代码：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:88)

### 2. III / IV-D Contact Policy：最具体规则优先的语义没有严格实现

论文要求多条规则同时命中时，取“最具体”的那一条。当前 `match()` 中只更新了 `budget`，没有同步更新 `best_pattern`，实现与论文描述不完全一致。

这不是文档问题，而是策略执行语义偏差，会直接影响 access control 的正确性。

相关代码：

- [saga/common/contact_policy.py](/home/kali/saga/saga/common/contact_policy.py:137)

### 3. IV-E Token 复用路径存在已知并发问题

`retrieve_valid_token()` 附近已有作者注释 `THIS CREATES A DEADLOCK`。这属于核心通信路径的稳定性问题，不修会影响 token reuse 场景的可信复现。

相关代码：

- [saga/agent.py](/home/kali/saga/saga/agent.py:428)

### 4. VI-B / VI-C：缺少论文结果级别的核心实验复现框架

当前仓库有 demo 脚本，但还不是论文结果级别的复现实验框架。至少还缺：

- 可重复采集 protocol overhead 的脚本
- 可重复采集 task completion 时间的脚本
- 统一记录结果并生成论文中表格/图所需原始数据的方式

现状更接近“功能演示”，还不能直接算“复现论文实验结果”。

相关代码：

- [experiments/schedule_meeting.py](/home/kali/saga/experiments/schedule_meeting.py:70)
- [experiments/expense_report.py](/home/kali/saga/experiments/expense_report.py:69)
- [experiments/create_blogpost.py](/home/kali/saga/experiments/create_blogpost.py:43)

### 5. Calendar 任务成功判定比论文目标弱

会议实验当前只校验了部分条件，代码里也留下了 TODO，没有验证“只有目标参与者被邀请”等更严格条件。这会削弱任务完成正确性的证明力度。

相关代码：

- [experiments/schedule_meeting.py](/home/kali/saga/experiments/schedule_meeting.py:18)

## 建议补

### 6. IV-B User Registration：补上外部身份验证 / human verification

论文中用户注册依赖外部身份验证语义；当前实现是本地密码 + JWT。若只看协议主干，这不阻塞跑通，但它与论文的治理前提并不完全一致。

相关代码：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:101)

### 7. IV-C Agent Registration：OTK 签名内容应绑定 agent identity

论文写的是对 `⟨aid, OTK⟩` 进行签名；当前代码只对 `OTK` bytes 本身签名。协议主线能跑，但与论文规范仍有偏差。

相关代码：

- [saga/user/user.py](/home/kali/saga/saga/user/user.py:247)
- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:320)

### 8. IV-E Token 参数应配置化，而不是硬编码

论文把 token lifetime 和 request quota 视为安全/性能权衡参数。当前实现固定为：

- `expiration_timestamp = issue_timestamp + timedelta(hours=1)`
- `Q_MAX = 50`

建议把这两个参数纳入配置文件或 user/agent policy。

相关代码：

- [saga/agent.py](/home/kali/saga/saga/agent.py:314)
- [saga/config.py](/home/kali/saga/saga/config.py:74)

### 9. VI-C 三个任务的结果校验可进一步贴近论文

现有三个任务都有成功判定，但校验强度不一致：

- `expense_report.py` 相对完整
- `create_blogpost.py` 仅检查是否保存、标题是否匹配
- `schedule_meeting.py` 缺少更严格参与者校验

建议补成统一的任务验收标准。

相关代码：

- [experiments/expense_report.py](/home/kali/saga/experiments/expense_report.py:17)
- [experiments/create_blogpost.py](/home/kali/saga/experiments/create_blogpost.py:17)
- [experiments/schedule_meeting.py](/home/kali/saga/experiments/schedule_meeting.py:18)

### 10. Appendix E 攻击复现缺少自动断言与批量化

当前 A1/A2/A3/A4/A5/A6/A8 已有脚本映射，但更像手工 demo，而不是稳定的回归测试或批量复现套件。

建议补：

- 每个攻击的 expected outcome 断言
- 批量执行入口
- 统一日志与结果摘要

相关代码：

- [experiments/adversary.py](/home/kali/saga/experiments/adversary.py:36)
- [experiments/README.md](/home/kali/saga/experiments/README.md:1)

### 11. Appendix D 形式化验证还缺一键验收入口

`proofs` 目录已经包含 ProVerif / Verifpal 模型，基础很好。但要把它变成真正的“复现材料”，还可以补：

- 一键运行脚本
- 固定输出目录
- 自动保存证明结果摘要

相关代码：

- [proofs/README.md](/home/kali/saga/proofs/README.md:1)

### 12. V-B A2A：如需认领论文该声明，仍需补完整适配层

如果只关注 SAGA 主线，这项可以暂不做；但若要严格覆盖论文中“实现了 A2A 集成”的说法，则当前仓库还缺标准 A2A card/request 的完整封装与收发层。

相关代码：

- [saga/provider/provider.py](/home/kali/saga/saga/provider/provider.py:354)

## 可忽略

### 13. `lookup()` 是残留接口

`Agent.lookup()` 调用了 `/lookup`，但 Provider 没有这个 endpoint。当前主路径走的是 `/access`，因此这是清理项，不是主线缺口。

相关代码：

- [saga/agent.py](/home/kali/saga/saga/agent.py:256)

### 14. README / 实验说明中的零散命令问题

部分攻击示例命令和说明文字不够严谨，但属于文档维护问题，不影响核心协议是否复现。

相关代码：

- [experiments/README.md](/home/kali/saga/experiments/README.md:5)

### 15. 日志与统计输出仍偏原型化

日志和 overhead 输出已经有基础，但格式和归档方式更像研究原型，不影响“协议是否存在”，主要影响“实验复现是否方便”。

## 最小补齐顺序

如果目标是优先把当前仓库推进到“论文主线可复现”，建议顺序如下：

1. 验证 `policy update / deactivate / OTK refresh` 的已有实现并补测试
2. 修 `contact policy specificity`
3. 修 `token cache deadlock`
4. 把 `token lifetime / quota` 配置化
5. 补 `3 tasks + overhead + attacks + proofs` 的统一复现 harness
6. 再决定是否补 `external identity` 和 `A2A`
