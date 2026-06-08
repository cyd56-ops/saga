<p align="center">
  <img src="assets/logo.png" alt="SAGA Logo" width="250"/>
</p>

<h1 align="center"><i>A Security Architecture for Governing AI Agentic Systems</i></h1>
<h3 align="center">Georgios Syros, Anshuman Suri, Jacob Ginesin, Cristina Nita-Rotaru, Alina Oprea</h3>

## Fork status: SAGA-PQ-CAN research prototype

This repository is currently used for two tracks:

1. SAGA reproduction track:
   reproduce and test the core SAGA protocol.
2. PQ-CAN extension track:
   add an optional agent-side runtime authentication gate after SAGA token validation.

PQ-CAN is not part of the original SAGA paper and does not replace SAGA Core.
It is an optional receiving-agent runtime extension.

## 当前 Fork 状态：SAGA-PQ-CAN 研究原型

本仓库目前包含两条工作线：

1. SAGA 复现轨道：
   复现并测试 SAGA 核心协议。
2. PQ-CAN 扩展轨道：
   在 SAGA token 校验之后，添加一个可选的 Agent 侧运行时认证 gate。

PQ-CAN 不是原始 SAGA 论文的一部分，也不替代 SAGA Core。
它是 receiving agent 侧的可选运行时扩展。

Recommended test commands in this fork:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest -q tests/security
.venv/bin/python -m pytest -q tests/integration
```

The current environment may not expose a plain `python` command consistently.
Prefer the repo-local `.venv/bin/python`.

## Abstract

Large Language Model (LLM)-based agents increasingly interact, collaborate, and delegate tasks to one another autonomously with minimal human interaction. Industry guidelines for agentic system governance emphasize the need for users to maintain comprehensive control over their agents, mitigating potential damage from malicious agents. Several proposed agentic system designs address agent identity, authorization, and delegation, but remain purely theoretical, without concrete implementation and evaluation. Most importantly, they do not provide user-controlled agent management.

To address this gap, we propose SAGA, a scalable Security Architecture for Governing Agentic systems, that offers user oversight over their agents’ lifecycle. In our design, users register their agents with a central entity, the Provider, that maintains agents contact information, user-defined access control policies, and helps agents enforce these policies on inter-agent communication. We introduce a cryptographic mechanism for deriving access control tokens, that offers fine-grained control over an agent’s interaction with other agents, providing formal security guarantees. We evaluate SAGA on several agentic tasks, using agents in different geolocations, and multiple on-device and cloud LLMs, demonstrating minimal performance overhead with no impact on underlying task utility in a wide range of conditions. Our architecture enables secure and trustworthy deployment of autonomous agents, accelerating the responsible adoption of this technology in sensitive environments.
<hr>

## Requirements

Install the `saga` package:

```bash
pip install -e .
```

Make sure that `mongoDB` is installed on the Provider side and the mongoDB server is up and running.

## Setup

To set things up, we will first begin by starting a `CA` server, followed by a `Provider` server for our SAGA protocol.

**Before you begin**: if you wish to run SAGA's core components (CA, Provider) locally, you need to set all the IPs in the `config.yaml` to `127.0.0.1`. An example of a local configuration can be found in [`config_local.yaml`](config_local.yaml). You can omit any steps that involve updating IPs in the following steps.

#### 1. Setup a CA

Generate valid credentials and host the *.crt, *.key, and *pub files at some endpoint.

```bash
python generate_credentials.py ca saga/ca/
```

One way to host these files is to run a simple fileserver, such as a python HTTP server.

```bash
cd saga/ca/ && python -m http.server
```

Take note of the `endpoint` where this CA is hosted and update it under `config.yaml` for the `ca`. If running locally, omit this step.

#### 2. Setup the Provider

Host this provider service at some endpoint by running the following command. This will automatically generate Provider credentials and get them signed by the CA:

```bash
cd saga/provider/ && python provider.py
```

Take note of the `endpoint` and update `config.yaml` for the `provider`. If running locally, omit this step.

### Troubleshooting
Certificates can sometimes be tricky. If you are getting SSL errors (e.g., `SSL: CERTIFICATE_VERIFY_FAILED`), it's most likely a `config.yaml` error. 

Whenever you update the config file, it's **always good practice** to delete previously generated `.key`, `.pub` and `.crt` files. You can find such keys and certificates in `saga/ca` and `saga/provider`.

## User Registration

Central to all user operations within the SAGA ecosystem is the `user.py` script.  It supports both interactive and automated usage modes.

Interactive use for manual control and input:
```bash
cd user/ && python user.py --interactive
```

Automated for predefined operations using a user configuration file (e.g., for registration and agent setup)::
```bash
cd saga/user/ && python3 user.py --uconfig /path/to/saga/user_configs/bob.yaml --register --register-agents
```

Now for the purposes of demonstration, assume the user `Bob` wants to register a new agent under the name `customagent`, an email client agent responsible for handling Bob's inbox. 

In order to register `customagent`, `Bob` first needs to be registered with the provider using the `register` endpoint:

```
======= SAGA User Client CLI =======
1. Register
2. Login
3. Register Agent
4. Exit
Choose an option: 1
Enter email: bob@mail.com
Enter password: bob
11:25:44 [USER] Generating user cryptographic material...
11:25:44 [CRYPTO] Saving user keys to /path/to/saga/user/keys/bob@mail.com
[...]
```
> __Note__: all generated cryptographic material for the user will be placed within a `keys/` subdirectory. The user's public/private keys will be stored in the `<uid>.pub` and `<uid>.key` format.

## Agent Registration

Before registering a new agent, `Bob` needs to authenticate themselves with the provider:

```bash
======= SAGA User Client CLI =======
1. Register
2. Login
3. Register Agent
4. Exit
Choose an option: 2           
Enter email: bob@mail.com
Enter password: bob
11:28:35 [PROVIDER] User bob@mail.com logged in successfully.
```

After successful authentication, `Bob` can register `customagent` with providing all the required material (agent device and networking information, cryptographic content, etc.) for `customagent` to operate within the SAGA network.

```bash
======= SAGA User Client CLI =======
1. Register
2. Login
3. Register Agent
4. Exit
Choose an option: 3
Enter agent name: customagent
Enter device name: alpha
Enter IP address: 127.0.0.1
Enter port: 12345
Enter number of one-time access keys: 10
Enter contact rulebook: [{"pattern":"*", "budget":10}]
11:29:05 [PROVIDER] Agent customagent registered successfully with stamp DNRD50sR3PFHqXjiG7Xuyq2d5fzALKaKtY2MS/8PoE9S//+pcNpGlOeKXOB1tnI/YRs4IL0XI/HlKV243LmcAQ==.
```

> __Note__: Once an agent has been successfully registered with the provider, a new subdirectory within the `user` directory, e.g. `user/<aid>` or in our case `user/bob@mail.com:customagent`. This is `customagent`'s woring directory. This directory contains the agent's manifest: `agent.json` listing the required metadata for the new agent to be able to operate within the SAGA network:

```json
{
    "aid": "bob@mail.com:customagent",
    "device": "alpha",
    "IP": "127.0.0.1",
    "port": 12345,
    "dev_info_sig": "Q78qQTDrrQRs77Kfe37IFQkU...",
    "agent_cert": "LS0tLS1CRUdJTiBDR...",
    "public_signing_key_sig": "mgVXMQo3zGLJD31700zkcdVlBmr...",
    "identity_key": "48qaThDW1vzO56sxzqh/WaphyO4BkuUa6V9Y+kHClUU=",
    "spk": "FLorcCb6WlYXqFFkHhBL55ErDp0ID4h0iXtNM1Kk2Es=",
    "spk_sig": "z4WU6gHCTE8RG3dgiBXD4UgzVV...",
    "opks": [
        "zogadPdg+j8lQNaXeiIo9rL1rPT33ykzBnFjsAx/Kzw=",
        ...
    ],
    ...
}
```

## Agent Communication

Once the new agent has been registered with the provider and its manifest has been created, the new SAGA agent can be run by simply creating a new saga `Agent` instance:

### Requirements

In order to instanciate a SAGA `Agent`, there are three things that are required:
- The agent working directory which contains the agent manifest `agent.json`.
- The agent metadata of the manifest (`agent.json`).
- A `AgentWrapper` instance which encapsulates a LLM Agent implementation e.g., a `smolagents` local agent.

### Kickstart Example

```python
from saga.agent import Agent, get_agent_material

# Gather required material
agent_workdir = "user/alice@mail.com:email_agent/"
agent_material = get_agent_material(agent_workdir)

# Create agent instance 
alice_email_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=<LLM_AGENT_WRAPPER>
)
# Goes online and can accept conversations from other agents
alice_email_agent.listen()
```

Once `listen` is invoked, the new agent goes online and other agents can start opening connections:

```python
from saga.agent import Agent, get_agent_material

# Gather required material
agent_workdir = "user/bob@mail.com:email_agent/"
agent_material = get_agent_material(agent_workdir)

# Create agent instance 
bob_email_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=<LLM_AGENT_WRAPPER>
)

# Attempts to start a new conversation with Alice's email agent.
bob_email_agent.connect("alice@mail.com:email_agent", "<QUERY>")
```

For the current research-only toy LWE path, you can also attach outbound signing
and receiving-side execution gating in one step:

```python
from pq import ToyLWESignatureScheme
from saga.agent import Agent, enable_toy_lwe_runtime_auth, get_agent_material

scheme = ToyLWESignatureScheme(seed=47)  # research-only, non-production
alice_keys = scheme.keygen()

agent_workdir = "user/alice@mail.com:email_agent/"
agent_material = get_agent_material(agent_workdir)
alice_email_agent = Agent(
    workdir=agent_workdir,
    material=agent_material,
    local_agent=<LLM_AGENT_WRAPPER>,
)

enable_toy_lwe_runtime_auth(
    alice_email_agent,
    scheme=scheme,
    key_pair=alice_keys,
    trusted_public_keys={
        "bob@mail.com:email_agent": b"<bob-toy-public-key-bytes>",
    },
)
```

This helper is only for the current toy/research path. Production-facing
post-quantum verification should continue to use a vetted backend through
`MLDSAAdapter` rather than the toy LWE scheme.

If you want an experiment entrypoint to enable the same research-only wiring
from configuration, add an optional `toy_runtime_auth` block under the target
agent:

```yaml
local_agent_config:
  model_type: "OpenAIServerModel"
  base_agent_type: "CodeAgent"
  api_base: "https://oai.codexi.eu.cc/v1"
  model: "gpt-5.2"
  tools: [calendar, self]
toy_runtime_auth:
  enabled: true
  mode: toy_compiled_research
  seed: 47
  verifier_flavor: compiled
  message_bytes: 32
  replay_state_dir: "/tmp/saga-pqcan-shared-replay"  # optional shared marker dir
  trusted_public_keys:
    bob@mail.com:email_agent: "<base64-encoded-toy-public-key>"
```

If `replay_state_dir` is omitted, the helper stores replay markers under the
receiving agent workdir at `audit/replay/`. Setting `replay_state_dir` lets
multiple local workdirs or gate instances share one replay marker directory.
This is a research file-store prototype; a real multi-host deployment should
inject a backend with equivalent atomic reserve semantics.

Supported runtime-auth modes are:

- `toy_compiled_research`: default research path; compiles the toy LWE verifier
  into the fixed verifier/CAN wiring.
- `toy_wrapper`: research comparison path that calls the toy verifier wrapper.
- `mldsa_external`: reserved for a vetted external ML-DSA backend; the current
  config-driven path fails closed unless explicit backend wiring is added.

Legacy configs that omit `mode` continue to infer `toy_compiled_research` from
`verifier_flavor: compiled` or `toy_wrapper` from `verifier_flavor: wrapper`.

In `toy_compiled_research`, the current compiled verifier boundary is explicit:
public matrix projections are fixed linear circuit steps, SHA-256 challenge
derivation stays deterministic preprocessing, and modular subtraction/equality
aggregation are deterministic hard gates. This prototype does not claim a
neural implementation of SHA-256 or a fully neuralized hash-to-challenge path.

The current `experiments/schedule_meeting.py`, `experiments/expense_report.py`,
and `experiments/create_blogpost.py` entrypoints will automatically call the
runtime helper when this block is present.

For a ready-made research-only example, see:

- `user_configs/emma_pqcan.yaml`
- `user_configs/raj_pqcan.yaml`

These sample configs wire the three task agents to each other with deterministic
toy LWE seeds and trusted toy public keys so the existing experiment entrypoints
can enable PQ-CAN runtime auth directly from YAML.

When a receiving-side request is rejected by the PQ-CAN execution gate, the
agent will also append a local JSONL audit record under
`<agent workdir>/audit/execution_gate.jsonl`.

PQ-CAN is an execution-surface authorization layer, not a replacement for SAGA
Core. SAGA still performs protocol admission, while the receiving-side runtime
gate decides whether a verified request may enter `llm_prompt`, `memory_read`,
`memory_write`, `tool_call`, `tool_call:<tool_name>`, or `delegation`. Agent-LLM
outputs may request scopes or describe intent, but the runtime gate makes the
final hard allow/deny decision. See [`SECURITY.md`](SECURITY.md) for the current
research security boundary and non-production cryptography status.

The experiment entrypoints also append a task-level structured result row under
`experiments/results/<task-name>.jsonl`, including the run mode, peer AID,
success outcome, and a summary of any receiver-side gate rejects observed in
that agent workdir.

You can validate saved end-to-end artifacts without starting services or calling
the model backend:

```bash
.venv/bin/python experiments/end_to_end_validation.py \
  --baseline-summary experiments/runs/20260527T114103Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json \
  --pq-can-summary experiments/runs/20260527T114953Z-schedule_meeting-expense_report-create_blogpost/end_to_end_stats_summary.json \
  --positive-task-count 3 \
  --real-negative-run-dir experiments/runs/20260531T122842Z-real-negative-missing_request_envelope-tampered_message-prompt_surface_tool_only-replayed_envelope-wrong_trusted_sender_key \
  --required-real-negative-scenario missing_request_envelope \
  --required-real-negative-scenario tampered_message \
  --required-real-negative-scenario prompt_surface_tool_only \
  --required-real-negative-scenario replayed_envelope \
  --required-real-negative-scenario wrong_trusted_sender_key
```

The validator checks that positive baseline/PQ-CAN summaries have the expected
runtime-auth mode, all tasks succeeded, positive gate reject counts are zero,
and real-service negative samples rejected with expected reasons without
invoking the recording local agent.

Users may use our implementation of a local LLM agent (available under `agent_backend`), but are free to implement their local agents using any library or manner as long as it inherits from the `LocalAgent` abstract class (defined under `local_agent.py`). The basic requirement is to implement the following function:

```python
def run(self, query: str,
            initiating_agent: bool,
            agent_instance: 'LocalAgent' = None,
            **kwargs) -> Tuple['LocalAgent', str]:
        """
        Run the local agent with the given query.

        Args:
            query (str): The query to run.
            initiating_agent (bool): Whether this is the agent that initiated the task or not.
            Can be helpful in using crafted prompts for the underlying model(s)
            agent_instance (LocalAgent, optional): An instance of LocalAgent to use.
            If provided, the agent class will not be reinitialized.
            We recommend not reusing agent classes, as most libraries attach minimal overhead to local agent wrappers, and reusing them can increase the attack surface for prompt injection and data leakage (as well as increase context window length).
            **kwargs: Additional keyword arguments.

        Returns:
            Tuple[LocalAgent, str]: A tuple containing the agent instance (a new one, if no agent instance was provided) and the result string.
        """
```



## Experiments

### Setup 

To get started, register the user using their configuration. We provide template user configs under `user_configs`. To register a user, run

```bash
cd saga/user
python user.py --register --uconfig ../../user_configs/emma.yaml
```

To register the agent(s) corresponding to this user, run

```bash
cd saga/user
python user.py --register-agents --uconfig ../../user_configs/emma.yaml
```

You can also register the user and agents in one go by providing both `--register` and `--register-agents` flags.

### Seed Data

Next, you can populate the "data" used by tools for each of the users by running:

```bash
cd experiments/
python seed_tool_data.py
```

This will use data from `experiments/data` to seed tool-related data for each user. Some of this seed data is based on the profiles used in the paper [Firewalls to Secure Dynamic LLM Agentic Networks](https://github.com/microsoft/Firewalled-Agentic-Networks), and is purely synthetic.

### Running tasks

The three tasks mentioned in the paper map to the following files under `experiments/`
- `schedule_meeting.py` : Scheduling agents coordinating to find a common time for a meeting and sending a calendar invite.
- `expense_report.py` : Email-reading agents coordinating to collect their expenses for a recent business trip, and one of them submits an expense report to HR.
- `create_blogpost.py` : Blogpost-writing agents use knowledge from prior blogposts of their users to collaborate and write a blogpost on some shared topic.

Before running a real task, run the read-only preflight check from the repo root:

```bash
.venv/bin/python experiments/preflight.py \
  --user-config user_configs/emma.yaml \
  --user-config user_configs/raj.yaml
```

This preflight does not modify local state. It verifies:

- `.ca_static/` and `saga/ca/` stay separate and expose the same CA public material
- `saga/provider/provider.crt` is signed by the current CA
- the referenced local user and agent certificates are signed by the current CA
- the local Provider database registrations match those local certificates

If you want guidance without automatic repair, ask for a repair plan:

```bash
.venv/bin/python experiments/preflight.py \
  --user-config user_configs/emma.yaml \
  --user-config user_configs/raj.yaml \
  --repair-plan
```

Before a real LLM-backed experiment, also run the optional model probe:

```bash
.venv/bin/python experiments/preflight.py \
  --user-config user_configs/emma.yaml \
  --user-config user_configs/raj.yaml \
  --skip-db-sync \
  --model-probe \
  --model-probe-timeout 5
```

The model probe sends a tiny chat-completions request to each configured
`OpenAIServerModel` endpoint. It can use network access and API quota, so it is
opt-in. If it fails, fix the model backend before starting the full task.

For a single-entry local rerun, use the batch runner. It waits for consecutive
successful model probes before starting local MongoDB, the CA static file
server, the Provider, tool-data seeding, and the selected listen/query task:

```bash
.venv/bin/python experiments/batch_run.py \
  --task schedule_meeting \
  --initiator-config user_configs/emma.yaml \
  --receiver-config user_configs/raj.yaml
```

Use `--task all` to run the three experiment entrypoints in sequence. Logs and
probe/preflight JSON are written under `experiments/runs/`.

Ordinary reruns should not regenerate the CA, restore `.bak` / `.selfsigned`
certificates into active paths, or mix `.ca_static/` with `saga/ca/` as a
single service/download directory.

To run a task, first start the receiving agent on its endpoint:

```bash
cd experiments/
python <task.py> listen ../user_configs/config1.yaml
```

Then, start the initiating agent on its respective endpoint

```bash
cd experiments/
python <task.py> query ../user_configs/config2.yaml ../user_configs/config1.yaml
```

The agent corresponding to `config2.yaml` will then contact `config1.yaml` and they work towards their shared goal.

> __Note__: Make sure you set `OPENAI_API_KEY` as an environment variable before running experiments.


### Agents without SAGA

While this package is designed to mainly support SAGA, you can use our local LLM implementation without SAGA i.e., set up LLM agents and manage their communication your way. One way to do so is to run the two agents and exposing their endpoints via a Flask Request- hardcoding each other's endpoints and communicating via these endpoints.

```python
from agent_backend.base import get_agent

# Assume some user_config was loaded
agent_of_interest_index = 0 # Whichever agent (out of all user agents) you wish to run
agent_of_interest = config.agents[agent_of_interest_index]

# Initialize the agent
local_agent = get_agent(
    config,
    agent_of_interest.local_agent_config
)

# Assume query was sent by another agent

# Query the agent
code_agent_instance, response = local_agent.run(
    query,
    initiating_agent=False, # Set to true if your agent started the conversation
    agent_instance=None, # Replace with self object in subsequent interactions
)

#.....

# In subsequent interactions, use code_agent_instance as agent_instance to keep track
_, response = local_agent.run(
    query,
    initiating_agent=False,
    agent_instance=code_agent_instance
)
```

## Citation

Please cite our work as follows for any purpose of usage.

```tex
@inproceedings{syros2026saga,
  title = {SAGA: A Security Architecture for Governing AI Agentic Systems},
  author={Georgios Syros and Anshuman Suri and Jacob Ginesin and Cristina Nita-Rotaru and Alina Oprea},
  booktitle = {Network and Distributed System Security (NDSS) Symposium},
  year = {2026}
}
```
