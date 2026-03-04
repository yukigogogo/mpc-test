package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"mpc-test/internal/mpc"
)

type TransferRequest struct {
	To     string `json:"to"`
	Amount int64  `json:"amount"`
}

type TransferRecord struct {
	TxID       string         `json:"txId"`
	From       string         `json:"from"`
	To         string         `json:"to"`
	Amount     int64          `json:"amount"`
	CreatedAt  time.Time      `json:"createdAt"`
	Message    string         `json:"message"`
	Signature  mpc.Signature  `json:"signature"`
	Transcript mpc.Transcript `json:"transcript"`
	VerifyOK   bool           `json:"verifyOk"`
}

type State struct {
	Address      string           `json:"address"`
	Balance      int64            `json:"balance"`
	Accounts     map[string]int64 `json:"accounts"`
	LastTransfer *TransferRecord  `json:"lastTransfer,omitempty"`
}

type Service struct {
	mu      sync.Mutex
	mpc     *mpc.Protocol
	address string
	balance int64
	ledger  map[string]int64
	last    *TransferRecord
}

func NewService() (*Service, error) {
	proto, err := mpc.NewProtocol()
	if err != nil {
		return nil, err
	}
	addr := proto.PublicKeyHex()
	return &Service{
		mpc:     proto,
		address: addr,
		balance: 1000,
		ledger: map[string]int64{
			addr:            1000,
			"demo-merchant": 0,
			"alice":         0,
		},
	}, nil
}

func (s *Service) GetState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	copyLedger := make(map[string]int64, len(s.ledger))
	for k, v := range s.ledger {
		copyLedger[k] = v
	}
	return State{Address: s.address, Balance: s.balance, Accounts: copyLedger, LastTransfer: s.last}
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

	msg := fmt.Sprintf("from=%s|to=%s|amount=%d|ts=%d", s.address, req.To, req.Amount, time.Now().UnixNano())
	sig, transcript, err := s.mpc.SignTransfer([]byte(msg))
	if err != nil {
		return nil, err
	}
	ok, err := mpc.Verify([]byte(msg), s.address, sig)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("mpc签名校验失败")
	}

	s.balance -= req.Amount
	s.ledger[s.address] = s.balance
	s.ledger[req.To] += req.Amount

	h := sha256.Sum256([]byte(msg + sig.RHex + sig.SHex))
	rec := &TransferRecord{
		TxID:       hex.EncodeToString(h[:]),
		From:       s.address,
		To:         req.To,
		Amount:     req.Amount,
		CreatedAt:  time.Now(),
		Message:    msg,
		Signature:  sig,
		Transcript: transcript,
		VerifyOK:   true,
	}
	s.last = rec
	return rec, nil
}

func Pretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
