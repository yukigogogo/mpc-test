# MPC Demo 代码流程说明（服务启动 -> DKG -> 签名 -> 验签 -> 转账）

> 本文档针对当前仓库实现，说明每个目录/函数负责什么，以及 DKG/签名/验签/转账如何串起来。

## 1. 服务启动

- `main.go`
  - 启动 HTTP 服务
  - 注册 `/api/state` `/api/transfer` `/api/benchmark`
  - 在启动时调用 `wallet.NewService()` 初始化所有协议对象。

## 2. 协议注册与实例化

- `internal/mpc/protocol.go`
  - `AvailableProtocols()` 返回稳定协议列表
  - `NewByName(name)` 创建对应协议实例（GG18/GG20/CGGMP21/FROST/EdDSA-TSS）

- `internal/mpc/protocols/*`
  - 每个文件定义协议配置（轮次、消息量、字节估算、安全假设）
  - 签名/验签委托给共享模拟器 `sim.Simulator`

## 3. 多节点网络与 DKG

- `internal/mpc/sim/simulator.go`
  - `type Node`：节点实体（`ID`、`Share`、`PublicKey`、`Paillier*`、`Net`）
  - `type Network`：本地 channel 网络（`Inbox`、`Send`）
  - `NewNetwork(n)` 初始化 n 节点网络
  - `GeneratePaillier(bits)` 生成真实 Paillier 密钥对（用于 CGGMP21/GG18/GG20 的 MtA）
  - `PaillierEncrypt/PaillierDecrypt/PaillierMulConst` 用于本地 MtA 同态乘法演示
  - `RandomPolynomial` / `EvaluatePolynomial` / `AggregateShares`：Shamir DKG 关键步骤
  - `runDKG()`：
    1) 每节点生成随机多项式
    2) 给其他节点发送 `s_ij`
    3) 每节点聚合得到 `x_j`
    4) 生成群公钥并下发到节点

## 4. 签名流程

- `signECDSALike()`（GG18/GG20/CGGMP21）
  - Round1: nonce commit
  - Round2: reveal & aggregate R
  - Round3: 基于 Paillier 的 MtA 消息
  - Round4: partial signature
  - Round5: combine signature

- `signSchnorrLike()`（FROST/EdDSA-TSS）
  - Round1: nonce commit
  - Round2: reveal + challenge + partial signature + combine

- 两条流程都会记录：
  - `Transcript.RoundLogs`
  - `Metrics`（轮次、消息数、字节量、签名耗时）

## 5. 验签流程

- `Verify()`
  - ECDSA 协议走 `ecdsa.Verify`
  - FROST/EdDSA-TSS 走 Schnorr 方程校验（`sG == R + eP`）

## 6. 钱包转账流程

- `internal/wallet/service.go`
  - `Transfer(req)`：
    1) 校验请求参数
    2) 根据 `req.Protocol` 选协议实例
    3) 组装消息并调用 `SignTransfer`
    4) 调用 `Verify` 本地验签
    5) 更新余额与账本
    6) 记录 `TransferRecord`（包含 `Signature`、`Transcript`、`Metrics`）

## 7. 前端展示

- `web/index.html`
  - 协议下拉选择
  - 调 `/api/transfer` 发起转账
  - 调 `/api/benchmark` 展示协议对比
  - 固定高度滚动区用于对比长 JSON

## 8. benchmark 流程

- `cmd/protocol-bench/main.go`
  - 循环所有协议
  - 重复执行 sign/verify
  - 输出 Markdown 表格与 CSV

- `scripts/run_protocol_benchmark.sh`
  - 一键运行 CLI
  - 落盘 `report.md` / `report.csv`
