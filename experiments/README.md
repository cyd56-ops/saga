## Dual-route Agent TLS receive-path runner

The opt-in R18 network runner exercises the actual `Agent.send`, `Agent.recv`,
and `Agent.receive_conversation` framing over a loopback TLS 1.3 connection:

```bash
../../.venv/bin/python experiments/dual_route_network_runner.py \
  --samples 3 \
  --mode route_b_with_a_shadow \
  --output /tmp/saga-dual-route-network.json
```

It generates short-lived TLS, ML-DSA, and toy Route A keys inside a temporary
directory. No key or credential is written to the repository. The report
records transport, Agent receive-path, and prompt-sink latency, plus replay and
tampered-signature no-side-effect evidence. It uses no artificial Route A
shadow delay.

This runner isolates the Agent receive path. It does not include Provider/CA
access handshakes, distributed state, a real LLM, or paper-scale repetitions;
those limitations are also embedded in the versioned JSON report.

## Attacker Models

How to recreate the attacks showcased in the paper:

## A1

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 1
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 1
```

## A2

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 2
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 2
```

## A3

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 3
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 3
```

## A4

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 4
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 4
```

## A5

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml None 5
```

Malicious:
```
python3 adversary.py query ../user_configs/alice.yaml ../user_configs/bob.yaml 5 ../user_configs/mallory.yaml
```

## A6

Benign:
```
python3 adversary.py listen ../user_configs/candice.yaml 6
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/candice.yaml 6
```

## A7

By the assumptions of the design of the system, such an attack will be prevented from the Human Verification service deployed from the Provider.

## A8

Benign:
```
python3 adversary.py listen ../user_configs/bob.yaml 8
```

Malicious:
```
python3 adversary.py query ../user_configs/mallory.yaml .. user_configs/bob.yaml 8
```
