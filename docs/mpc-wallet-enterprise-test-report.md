# MPC 钱包企业级开发测试先例文档（Demo 基线）

## 1. 文档目标

本报告用于给企业级 MPC 钱包研发提供一个“可复现实验基线”，围绕以下问题给出结构化结论：

1. 不同协议（GG18、GG20、CGGMP21、FROST、EdDSA-TSS）在同一业务操作下的性能差异如何。
2. 当前项目代码里，每个协议在架构中的落点是什么，如何切换与扩展。
3. 如何把测试结果作为后续“上链真实环境（AA/EOA）”改造前的决策输入。

> 说明：当前仓库是**教学/模拟系统**，协议实现由统一 simulator 驱动，不代表生产级密码协议安全实现。

---

## 2. 仓库目录分级（与测试相关）

```text
mpc-test/
├── cmd/
│   └── protocol-bench/
│       └── main.go                # 协议基准测试 CLI（输出 Markdown + CSV）
├── docs/
│   └── mpc-wallet-enterprise-test-report.md
├── internal/
│   ├── mpc/
│   │   ├── protocol.go            # 协议注册与工厂
│   │   ├── protocol_test.go       # 协议签名/验签闭环测试
│   │   ├── protocols/
│   │   │   ├── gg18/gg18.go
│   │   │   ├── gg20/gg20.go
│   │   │   ├── cggmp21/cggmp21.go
│   │   │   ├── frost/frost.go
│   │   │   └── eddsatss/eddsatss.go
│   │   └── sim/simulator.go       # 核心模拟签名与性能指标采集
│   ├── mpcapi/
│   │   └── types.go               # 协议统一接口与 Metrics/Transcript 类型
│   └── wallet/
│       ├── service.go             # 协议选择、转账签名验签、benchmark 聚合
│       └── service_test.go
├── scripts/
│   └── run_protocol_benchmark.sh  # 一键跑 benchmark，输出 report.md/report.csv
├── web/
│   └── index.html                 # 协议选择 + benchmark 可视化
└── main.go                        # HTTP API 入口
```

---

## 3. 协议原理概览（测试视角）

> 以下是工程决策层面的简化描述，用于选型比较，不是形式化安全证明。

### 3.1 GG18（ECDSA-TSS）
- 典型多轮交互门限 ECDSA 路线，历史应用广。
- 优点：工程资料多、生态成熟。
- 代价：轮次和消息通常偏高，网络延迟敏感。

### 3.2 GG20（ECDSA-TSS）
- 相比 GG18 进一步优化交互流程。
- 优点：在保留 ECDSA 兼容性的同时，减少部分通信成本。
- 代价：实现复杂度仍较高。

### 3.3 CGGMP21（ECDSA-TSS）
- 更现代的门限 ECDSA 方案之一，强调并发/组合安全语境。
- 优点：在性能和安全模型平衡上较好。
- 代价：实现、审计与工程集成门槛较高。

### 3.4 FROST（Schnorr threshold）
- 典型 2 轮 Schnorr 门限签名思想，交互效率高。
- 优点：网络轮次少，延迟场景优势明显。
- 代价：若目标链原生是 ECDSA（如 ETH EOA），需 AA/合约钱包路径或额外适配。

### 3.5 EdDSA-TSS
- 在 EdDSA 曲线体系下做门限签名。
- 优点：签名流程简洁，某些生态中性能表现稳定。
- 代价：与 EVM/ETH 原生 ECDSA 路线兼容需额外设计。

---

## 4. 代码实现详情（关键链路）

### 4.1 协议注册与实例化
- `AvailableProtocols()` 提供稳定协议列表。
- `NewByName()` 根据协议名创建实例，供钱包与 benchmark 统一调用。

### 4.2 协议统一接口
- `mpcapi.Protocol` 统一了：`SignTransfer` / `Verify` / `LastMetrics` / `StaticProfile` / `EncryptedShareExample`。
- 使前端、钱包服务、benchmark CLI 不依赖具体协议细节。

### 4.3 协议实现方式
- `internal/mpc/protocols/*` 是轻量适配器层：每个协议定义参数（Rounds、Messages、BytesBase、安全画像），实际签名验签逻辑委托 `sim.Simulator`。
- `sim` 负责：
  - Schnorr 风格 sign/verify 流程（教学实现）
  - 指标采集（耗时、消息量、字节估算）
  - Transcript 日志
  - 加密份额快照示例（AES-GCM）

### 4.4 钱包服务与 Web 输出
- `wallet.Service.Transfer` 按请求协议签名，并把 `Metrics` 记录到 `TransferRecord`。
- `wallet.Service.Benchmark` 遍历所有协议生成对比数据。
- `main.go` 暴露 `/api/benchmark`，`web/index.html` 可直接展示结果。

---

## 5. 测试方法与参数

测试工具：`scripts/run_protocol_benchmark.sh`（底层调用 `cmd/protocol-bench`）

本次参数：
- 每协议迭代次数：200
- 消息大小：256 bytes
- 网络模型：RTT = 20ms，带宽 = 50Mbps

命令：

```bash
./scripts/run_protocol_benchmark.sh benchmark-output
```

---

## 6. 实测性能数据（本次运行）

| Protocol | Rounds | Messages | Bytes/Op | Sign Avg (ms) | Verify Avg (ms) | CPU Work Avg (ms) | Network Est. (ms) | End-to-End TPS |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| FROST | 2 | 4 | 1924 | 11.030 | 11.545 | 22.575 | 40.308 | 15.903 |
| EdDSA-TSS | 3 | 5 | 2380 | 11.118 | 11.806 | 22.924 | 60.381 | 12.004 |
| CGGMP21 | 6 | 8 | 5048 | 10.863 | 11.543 | 22.406 | 120.808 | 6.983 |
| GG20 | 7 | 10 | 5960 | 11.293 | 11.827 | 23.120 | 140.954 | 6.095 |
| GG18 | 9 | 14 | 7784 | 10.816 | 11.508 | 22.324 | 181.245 | 4.912 |

### 6.1 数据解读（企业选型视角）

1. **网络主导型差异明显**：本组数据中 CPU 工作时间接近（约 22~23ms），协议间 TPS 差距主要来自轮次与字节量。
2. **低轮次协议优势清晰**：FROST / EdDSA-TSS 在 RTT 模型下吞吐显著更高。
3. **ECDSA 路线中折中选择**：若必须兼容 ECDSA，CGGMP21/GG20 相比 GG18 通信效率更优。

---

## 7. 企业级开发建议（从该测试先例出发）

### 7.1 若目标是 ETH EOA 兼容
优先考虑 ECDSA-TSS 路线（GG18/GG20/CGGMP21），在真实链路加入：
- HSM/KMS 托管份额
- 可审计 nonce 生命周期
- 节点故障与超时重试机制

### 7.2 若目标是 AA/智能合约钱包
可考虑 FROST/Schnorr 聚合签名路线，但需新增：
- 合约钱包（Solidity）验签逻辑
- EIP-4337 EntryPoint/Bundler/Paymaster 对接
- 链上 gas 与失败回滚策略验证

### 7.3 测试体系升级建议
- 增加长时压测（1h/6h/24h）
- 增加多机房 RTT 场景（20/80/150ms）
- 增加异常注入（节点离线、网络抖动、nonce 冲突）
- 增加链上真实广播 KPI（成功率、确认时延、gas）

---

## 8. 可复现命令清单

```bash
# 单元测试
go test ./...

# 生成协议对比报告（markdown + csv）
./scripts/run_protocol_benchmark.sh benchmark-output

# 自定义参数示例
ITER=500 MSG_SIZE=512 RTT_MS=30 BANDWIDTH_MBPS=20 ./scripts/run_protocol_benchmark.sh benchmark-output
```

---

## 9. 结论（当前 Demo 结论）

- 该项目已具备“多协议同接口、同操作、同指标”的对比能力，可作为企业前期选型的技术预研基线。
- 在当前参数下，FROST 与 EdDSA-TSS 显示更优的网络效率；若必须 ECDSA 兼容，CGGMP21/GG20 相对 GG18 更具通信性能优势。
- 下一阶段应把该测试先例扩展到真实链路与安全基础设施，形成可上线前的完整验收链条。
