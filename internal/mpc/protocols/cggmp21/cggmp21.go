package cggmp21

import (
	"mpc-test/internal/mpc/sim"
	"mpc-test/internal/mpcapi"
)

type Protocol struct{ s *sim.Simulator }

// New 构造该协议模拟器，并提供用于前端对比的协议配置。
func New() (*Protocol, error) {
	s, err := sim.NewSimulator(sim.Config{ProtocolName: "CGGMP21", Rounds: 6, Messages: 8, BytesBase: 3000,
		Security: mpcapi.SecurityProfile{Assumption: "离散对数 + UC安全证明", ThresholdSupport: "t-of-n", NonceRequirement: "并发场景下必须唯一nonce"}})
	if err != nil {
		return nil, err
	}
	return &Protocol{s: s}, nil
}
func (p *Protocol) Name() string         { return "CGGMP21" }          // 返回协议名
func (p *Protocol) PublicKeyHex() string { return p.s.PublicKeyHex() } // 返回协议公钥地址
func (p *Protocol) SignTransfer(msg []byte) (mpcapi.Signature, mpcapi.Transcript, error) {
	return p.s.Sign(msg) // 委托共享模拟器签名
}
func (p *Protocol) Verify(msg []byte, sig mpcapi.Signature) (bool, error) {
	return p.s.Verify(msg, sig) // 委托共享模拟器验签
}
func (p *Protocol) LastMetrics() mpcapi.Metrics   { return p.s.LastMetrics() }           // 返回最近一次签名指标
func (p *Protocol) StaticProfile() mpcapi.Metrics { return p.s.StaticProfile() }         // 返回静态协议画像
func (p *Protocol) EncryptedShareExample() string { return p.s.EncryptedShareExample() } // 返回加密份额示例
