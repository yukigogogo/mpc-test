package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"mpc-test/internal/mpc"
	"mpc-test/internal/mpcapi"
)

type TransferRequest struct {
	To       string `json:"to"`       // 收款账户标识（可理解为地址或昵称）
	Amount   int64  `json:"amount"`   // 本次转账金额（最小单位）
	Protocol string `json:"protocol"` // 指定签名协议，如 GG18/FROST 等
}

type TransferRecord struct {
	TxID                   string            `json:"txId"`                   // 交易哈希（演示用）
	From                   string            `json:"from"`                   // 付款地址（协议对应公钥）
	To                     string            `json:"to"`                     // 收款地址
	Amount                 int64             `json:"amount"`                 // 转账金额
	CreatedAt              time.Time         `json:"createdAt"`              // 交易创建时间
	Protocol               string            `json:"protocol"`               // 使用的 MPC 协议名
	Message                string            `json:"message"`                // 被签名原文消息
	Signature              mpcapi.Signature  `json:"signature"`              // 最终聚合签名
	Transcript             mpcapi.Transcript `json:"transcript"`             // 签名轮次日志
	VerifyOK               bool              `json:"verifyOk"`               // 本地验签结果
	EncryptedShareSnapshot string            `json:"encryptedShareSnapshot"` // 密钥份额加密快照（演示）
	Metrics                mpcapi.Metrics    `json:"metrics"`                // 协议性能/网络/安全画像
}

type State struct {
	AddressByProtocol map[string]string `json:"addressByProtocol"`      // 每个协议对应的地址
	Balance           int64             `json:"balance"`                // 当前钱包余额
	Accounts          map[string]int64  `json:"accounts"`               // 简化账本
	Protocols         []string          `json:"protocols"`              // 可选协议列表
	LastTransfer      *TransferRecord   `json:"lastTransfer,omitempty"` // 最近一笔交易
}

type Service struct {
	mu       sync.Mutex
	protocol map[string]mpcapi.Protocol
	balance  int64
	ledger   map[string]int64
	last     *TransferRecord
}

func NewService() (*Service, error) {
	// 协议实例容器：key 是协议名，value 是具体协议对象。
	protos := map[string]mpcapi.Protocol{}
	// 遍历所有可用协议并逐个初始化。
	for _, name := range mpc.AvailableProtocols() {
		p, err := mpc.NewByName(name)
		if err != nil {
			// 任一协议初始化失败，直接返回错误，避免服务半可用。
			return nil, err
		}
		// 放入协议索引表，后续 Transfer 可按协议名查找。
		protos[name] = p
	}
	// 初始化演示账本：两个外部账户从 0 开始。
	ledger := map[string]int64{"demo-merchant": 0, "alice": 0}
	// 给每个协议地址分配演示初始余额（各协议地址独立）。
	for _, p := range protos {
		ledger[p.PublicKeyHex()] = 1000
	}
	// 返回 service 实例。
	return &Service{protocol: protos, balance: 1000, ledger: ledger}, nil
}

func (s *Service) GetState() State {
	// 加锁保护共享状态（余额、账本、最近交易）。
	s.mu.Lock()
	defer s.mu.Unlock()
	// 复制账本，避免外部拿到内部 map 指针后篡改数据。
	copyLedger := make(map[string]int64, len(s.ledger))
	for k, v := range s.ledger {
		copyLedger[k] = v
	}
	// 按协议导出地址，便于前端展示“同钱包不同协议地址”。
	addr := map[string]string{}
	for name, p := range s.protocol {
		addr[name] = p.PublicKeyHex()
	}
	// 返回完整状态快照。
	return State{AddressByProtocol: addr, Balance: s.balance, Accounts: copyLedger, Protocols: mpc.AvailableProtocols(), LastTransfer: s.last}
}

func (s *Service) Transfer(req TransferRequest) (*TransferRecord, error) {
	// 全流程加锁，确保并发时账本与余额的一致性。
	s.mu.Lock()
	defer s.mu.Unlock()
	// 校验转账金额必须为正数。
	if req.Amount <= 0 {
		return nil, fmt.Errorf("amount 必须大于0")
	}
	// 校验收款方不能为空。
	if req.To == "" {
		return nil, fmt.Errorf("to 不能为空")
	}
	// 校验余额是否足够。
	if s.balance < req.Amount {
		return nil, fmt.Errorf("余额不足")
	}
	// 未指定协议时默认走 FROST（交互轮次最少，体验快）。
	if req.Protocol == "" {
		req.Protocol = "FROST"
	}
	// 按协议名找到对应协议实例。
	p, ok := s.protocol[req.Protocol]
	if !ok {
		return nil, fmt.Errorf("协议不存在: %s", req.Protocol)
	}

	// 付款地址 = 当前协议实例的公钥地址。
	from := p.PublicKeyHex()
	// 组装被签名消息：将关键业务字段串联，防止上下文丢失。
	msg := fmt.Sprintf("from=%s|to=%s|amount=%d|protocol=%s|ts=%d", from, req.To, req.Amount, req.Protocol, time.Now().UnixNano())
	// 执行 MPC 签名流程，拿到签名与轮次日志。
	sig, transcript, err := p.SignTransfer([]byte(msg))
	if err != nil {
		return nil, err
	}
	// 对生成签名做一次本地验签，作为流程自检。
	verifyOK, err := p.Verify([]byte(msg), sig)
	if err != nil {
		return nil, err
	}
	// 验签失败直接拒绝记账，保证“先验签后入账”。
	if !verifyOK {
		return nil, fmt.Errorf("mpc签名校验失败")
	}

	// 扣减钱包余额。
	s.balance -= req.Amount
	// 更新付款地址余额。
	s.ledger[from] = s.balance
	// 更新收款地址余额。
	s.ledger[req.To] += req.Amount

	// 计算交易 ID：用消息和签名拼接后做 sha256。
	h := sha256.Sum256([]byte(msg + sig.RHex + sig.SHex))
	rec := &TransferRecord{
		TxID: hex.EncodeToString(h[:]), From: from, To: req.To, Amount: req.Amount, CreatedAt: time.Now(),
		Protocol: req.Protocol, Message: msg, Signature: sig, Transcript: transcript, VerifyOK: true,
		EncryptedShareSnapshot: p.EncryptedShareExample(), Metrics: p.LastMetrics(),
	}
	// 记录最近一笔交易，供前端快速展示。
	s.last = rec
	// 返回交易详情。
	return rec, nil
}

func (s *Service) Benchmark() []mpcapi.Metrics {
	// 加锁读取协议 map，防止并发修改。
	s.mu.Lock()
	defer s.mu.Unlock()
	// 预分配切片容量，减少扩容开销。
	result := make([]mpcapi.Metrics, 0, len(s.protocol))
	// 固定协议顺序遍历，方便前端稳定展示。
	for _, name := range mpc.AvailableProtocols() {
		p := s.protocol[name]
		// benchmark 输入消息固定，方便横向对比。
		msg := []byte("benchmark-message")
		// 若签名成功，记录实时指标。
		if _, _, err := p.SignTransfer(msg); err == nil {
			result = append(result, p.LastMetrics())
		} else {
			// 若签名失败，至少输出静态画像，避免前端空白。
			result = append(result, p.StaticProfile())
		}
	}
	// 返回所有协议指标。
	return result
}

func Pretty(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
