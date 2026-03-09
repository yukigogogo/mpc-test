# MPC 钱包企业级测试先例报告（最新重生成）

## 1. 目的与范围

本报告基于当前仓库最新代码重新生成，作为企业级 MPC 钱包研发的测试先例，目标是回答：

- 不同协议在同一操作下（签名/验签）性能、网络、吞吐差异。
- 现有代码架构如何映射到协议实现与测试路径。
- 在“协议选型”阶段可直接使用哪些结论。

> 说明：本项目为工程对比 demo，协议流程为统一模拟框架，不直接等价于生产级密码学实现。

---

## 2. 测试环境与参数

- 基准命令：`./scripts/run_protocol_benchmark.sh benchmark-output`
- 每协议迭代次数：`200`
- 消息大小：`256 bytes`
- 网络模型：`RTT=20ms`，`带宽=50Mbps`

测试对象：
- GG18
- GG20
- CGGMP21
- FROST
- EdDSA-TSS

---

## 3. 代码结构（目录分级）

```text
mpc-test/
├── cmd/protocol-bench/main.go               # 协议对比 benchmark CLI
├── scripts/run_protocol_benchmark.sh        # 一键生成 Markdown + CSV
├── internal/mpc/protocol.go                 # 协议列表与工厂
├── internal/mpc/sim/simulator.go            # 模拟签名、验签、指标采集
├── internal/mpc/protocols/*                 # 各协议适配器
├── internal/mpcapi/types.go                 # Protocol/Metrics/Transcript 抽象
├── internal/wallet/service.go               # 协议化转账与记录
├── web/index.html                           # 协议选择、交易与对比展示
└── main.go                                  # API 入口
```

---

## 4. 各协议原理（工程视角简述）

### GG18（ECDSA-TSS）
- 多轮交互门限 ECDSA 经典方案。
- 优点：生态成熟。
- 劣势：轮次与通信量通常较高。

### GG20（ECDSA-TSS）
- GG18 的优化路线之一。
- 优点：通信成本相对更优。
- 劣势：工程复杂度仍然较高。

### CGGMP21（ECDSA-TSS）
- 新一代门限 ECDSA 路线，关注并发与安全模型。
- 优点：在性能与安全语义上更均衡。
- 劣势：实现与审计成本较高。

### FROST（Schnorr Threshold）
- 两轮交互特征明显，网络效率高。
- 优点：高延迟网络场景吞吐优势突出。
- 劣势：在 ETH EOA 原生兼容路径上需要额外适配（AA/合约钱包路线）。

### EdDSA-TSS
- EdDSA 曲线体系下的门限签名路线。
- 优点：流程简洁，性能表现稳定。
- 劣势：与 EVM 原生 ECDSA 兼容需单独设计。

---

## 5. 实测数据（本次重新生成）

| Protocol | Rounds | Messages | Bytes/Op | Sign Avg (ms) | Verify Avg (ms) | CPU Work Avg (ms) | Network Est. (ms) | End-to-End TPS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FROST | 2 | 4 | 1924 | 10.914 | 11.603 | 22.518 | 40.308 | 15.917 |
| EdDSA-TSS | 3 | 5 | 2380 | 10.747 | 11.366 | 22.113 | 60.381 | 12.122 |
| CGGMP21 | 6 | 8 | 5048 | 10.952 | 11.474 | 22.426 | 120.808 | 6.982 |
| GG20 | 7 | 10 | 5960 | 10.657 | 11.298 | 21.955 | 140.954 | 6.138 |
| GG18 | 9 | 14 | 7784 | 10.782 | 11.368 | 22.150 | 181.245 | 4.917 |

---

## 6. 结果分析与选型建议

1. **网络因素是主要差异来源**：CPU 工作时间都在 ~22ms，TPS 差距主要来自轮次与字节量。
2. **低轮次协议在高 RTT 下优势明显**：FROST、EdDSA-TSS 吞吐领先。
3. **若必须兼容 ECDSA（ETH EOA 路线）**：GG20/CGGMP21 相比 GG18 更适合作为优先评估对象。

---

## 7. 面向企业落地的下一步

- 引入真实链路指标：链上确认时延、失败率、Gas 成本。
- 增加稳定性测试：长稳压测（1h/6h/24h）。
- 增加异常注入：网络抖动、节点超时、nonce 冲突。
- 安全工程化：HSM/KMS、审计日志、密钥生命周期治理。

---

## 8. 复现命令

```bash
# 单元测试
go test ./...

# 生成 benchmark 报告（markdown + csv）
./scripts/run_protocol_benchmark.sh benchmark-output
```
