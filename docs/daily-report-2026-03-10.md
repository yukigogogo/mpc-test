# 2026/03/10 工作日报

## task1 - MPC钱包TSS架构落地（real 方向重构）

### 任务需求
将当前项目从统一 `sim` 入口改为更贴近真实协议工程结构：
- 删除旧 `sim` 目录
- 采用按协议分发签名入口
- 保留多节点 + DKG + MtA + 指标链路

### 今日完成
1. **目录重构**
   - 删除 `internal/mpc/sim` 目录。
   - 新增 `internal/mpc/real/runtime.go`，承载多节点运行时。
2. **多节点与DKG保留并迁移**
   - 保留 `Node/Network/Message` 结构。
   - 保留 `RandomPolynomial/EvaluatePolynomial/AggregateShares/runDKG`。
3. **真实 Paillier 加密链路（工程级）**
   - 实现 `GeneratePaillier(bits)`、`PaillierEncrypt`、`PaillierDecrypt`、`PaillierMulConst`。
   - 在 ECDSA-like Round3 中使用 Paillier 同态乘法流程模拟 MtA。
4. **签名入口改造（按协议分发）**
   - `Sign()` 按协议路由到 `signGG18/signGG20/signCGGMP21/signFROST/signEdDSA`。
   - 为后续接 Binance / ZenGo / Rust FROST 真实库预留清晰入口。
5. **协议适配器更新**
   - `internal/mpc/protocols/*` 从 `sim` 依赖切换为 `real` 依赖。
6. **文档同步**
   - 更新代码流程文档中的目录与函数路径。

### 测试验证
- `go test ./...` 通过。
- `./scripts/run_protocol_benchmark.sh benchmark-output` 可产出最新报告。

### 当前结论
- 已完成“从统一 simulator 目录到 real 运行时目录”的结构性迁移。
- 已具备协议级签名函数入口，不再是单一路径。
- 下一步可逐个协议替换为外部真实实现库调用（GG18/GG20/CGGMP21/FROST/EdDSA-TSS）。

---

## task2 - 开源钱包架构对标与签名/私钥层分析

### 任务需求
参考开源钱包实现，沉淀可落地的签名与密钥层架构模式。

### 今日完成
1. 基于本项目现状，形成“服务启动 -> 协议实例化 -> DKG -> 签名 -> 验签 -> 转账”的函数级映射文档。
2. 将 `real runtime` 与协议适配层边界明确：
   - 协议适配层负责配置与路由。
   - 运行时负责节点网络、DKG、签名轮次执行。
3. 形成可继续替换真实库的工程切入点清单（每协议独立 `signXxx` / 后续 `dkgXxx`）。

### 文档留存
- `docs/mpc-dkg-sign-transfer-codeflow.md`
- `docs/daily-report-2026-03-10.md`
