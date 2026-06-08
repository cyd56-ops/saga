# GPT-5.4 Live Ablation Results (n=2)

This archive combines two live end-to-end `gpt-5.4` samples for the real runtime modes currently wired in the prototype: SAGA baseline and Shamir-secured PQ-CAN. Each sample runs `schedule_meeting`, `expense_report`, and `create_blogpost`.

## Run-Level Aggregate

| mode | live runs | tasks | success | runtime auth | mean total latency / run | total latency range / run | mean model calls / run | model call range / run | audit rejects | cost/token fields |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | 2 | 6 | 6/6 | false | 102.979934 s | 98.898812-107.061056 s | 12.5 | 12-13 | 0 | unavailable |
| pq_can | 2 | 6 | 6/6 | true | 123.077188 s | 122.918774-123.235601 s | 11.5 | 8-15 | 0 | unavailable |

## Task-Latency Aggregate

| mode | mean task latency | task latency range | total model calls | audit records | audit rejects |
| --- | --- | --- | --- | --- | --- |
| baseline | 34.326645 s | 18.573237-59.334295 s | 25 | 0 | 0 |
| pq_can | 41.025729 s | 14.310630-82.046452 s | 23 | 0 | 0 |

## Paper Text Draft

Across two live `gpt-5.4` runs, the SAGA baseline completed all six positive tasks, and the Shamir-secured PQ-CAN runtime also completed all six positive tasks. PQ-CAN kept `runtime_auth_enabled=true` throughout the run and produced zero execution-gate audit rejects on the positive workload. The mean total task latency per three-task run was 102.98 s for the baseline and 123.08 s for PQ-CAN, a 20.10 s absolute increase or 1.20x ratio in this small live sample. Model call counts varied across runs and should be treated as model/runtime variability rather than cryptographic gate overhead. API cost and token usage remain unavailable because the model backend did not expose explicit usage or cost fields.

## Source Artifacts

| sample | baseline summary | pq_can summary |
| --- | --- | --- |
| 20260605T064325Z | `experiments/runs/20260605T064325Z-real-e2e-ablation/saga_only/end_to_end_stats_summary.json` | `experiments/runs/20260605T064325Z-real-e2e-ablation/shamir_secured_pq_can/end_to_end_stats_summary.json` |
| 20260605T-repeat | `experiments/runs/20260605T-repeat-gpt54-real-e2e-ablation/saga_only/end_to_end_stats_summary.json` | `experiments/runs/20260605T-repeat-gpt54-real-e2e-ablation/shamir_secured_pq_can/end_to_end_stats_summary.json` |

Ordinary PQ middleware and naive neural verifier remain offline ablation modes until dedicated real-runtime adapters are added.
