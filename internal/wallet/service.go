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
	To       string `json:"to"`
	Amount   int64  `json:"amount"`
	Protocol string `json:"protocol"`
}

type TransferRecord struct {
	TxID                   string            `json:"txId"`
	From                   string            `json:"from"`
	To                     string            `json:"to"`
	Amount                 int64             `json:"amount"`
	CreatedAt              time.Time         `json:"createdAt"`
	Protocol               string            `json:"protocol"`
	Message                string            `json:"message"`
	Signature              mpcapi.Signature  `json:"signature"`
	Transcript             mpcapi.Transcript `json:"transcript"`
	VerifyOK               bool              `json:"verifyOk"`
	EncryptedShareSnapshot string            `json:"encryptedShareSnapshot"`
	Metrics                mpcapi.Metrics    `json:"metrics"`
}

type State struct {
	AddressByProtocol map[string]string `json:"addressByProtocol"`
	Balance           int64             `json:"balance"`
	Accounts          map[string]int64  `json:"accounts"`
	Protocols         []string          `json:"protocols"`
	LastTransfer      *TransferRecord   `json:"lastTransfer,omitempty"`
}

type Service struct {
	mu       sync.Mutex
	protocol map[string]mpcapi.Protocol
	balance  int64
	ledger   map[string]int64
	last     *TransferRecord
}

func NewService() (*Service, error) {
	protos := map[string]mpcapi.Protocol{}
	for _, name := range mpc.AvailableProtocols() {
		p, err := mpc.NewByName(name)
		if err != nil {
			return nil, err
		}
		protos[name] = p
	}
	ledger := map[string]int64{"demo-merchant": 0, "alice": 0}
	for _, p := range protos {
		ledger[p.PublicKeyHex()] = 1000
	}
	return &Service{protocol: protos, balance: 1000, ledger: ledger}, nil
}

func (s *Service) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyLedger := make(map[string]int64, len(s.ledger))
	for k, v := range s.ledger {
		copyLedger[k] = v
	}
	addr := map[string]string{}
	for name, p := range s.protocol {
		addr[name] = p.PublicKeyHex()
	}
	return State{AddressByProtocol: addr, Balance: s.balance, Accounts: copyLedger, Protocols: mpc.AvailableProtocols(), LastTransfer: s.last}
}

func (s *Service) Transfer(req TransferRequest) (*TransferRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Amount <= 0 {
		return nil, fmt.Errorf("amount 必须大于0")
	}
	if req.To == "" {
		return nil, fmt.Errorf("to 不能为空")
	}
	if s.balance < req.Amount {
		return nil, fmt.Errorf("余额不足")
	}
	if req.Protocol == "" {
		req.Protocol = "FROST"
	}
	p, ok := s.protocol[req.Protocol]
	if !ok {
		return nil, fmt.Errorf("协议不存在: %s", req.Protocol)
	}

	from := p.PublicKeyHex()
	msg := fmt.Sprintf("from=%s|to=%s|amount=%d|protocol=%s|ts=%d", from, req.To, req.Amount, req.Protocol, time.Now().UnixNano())
	sig, transcript, err := p.SignTransfer([]byte(msg))
	if err != nil {
		return nil, err
	}
	verifyOK, err := p.Verify([]byte(msg), sig)
	if err != nil {
		return nil, err
	}
	if !verifyOK {
		return nil, fmt.Errorf("mpc签名校验失败")
	}

	s.balance -= req.Amount
	s.ledger[from] = s.balance
	s.ledger[req.To] += req.Amount

	h := sha256.Sum256([]byte(msg + sig.RHex + sig.SHex))
	rec := &TransferRecord{
		TxID: hex.EncodeToString(h[:]), From: from, To: req.To, Amount: req.Amount, CreatedAt: time.Now(),
		Protocol: req.Protocol, Message: msg, Signature: sig, Transcript: transcript, VerifyOK: true,
		EncryptedShareSnapshot: p.EncryptedShareExample(), Metrics: p.LastMetrics(),
	}
	s.last = rec
	return rec, nil
}

func (s *Service) Benchmark() []mpcapi.Metrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]mpcapi.Metrics, 0, len(s.protocol))
	for _, name := range mpc.AvailableProtocols() {
		p := s.protocol[name]
		msg := []byte("benchmark-message")
		if _, _, err := p.SignTransfer(msg); err == nil {
			result = append(result, p.LastMetrics())
		} else {
			result = append(result, p.StaticProfile())
		}
	}
	return result
}

func Pretty(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }
