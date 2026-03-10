package gg18

import (
	"mpc-test/internal/mpc/real"
	"mpc-test/internal/mpcapi"
)

type Protocol struct{ s *real.Runtime }

// New 构造 GG18 协议模拟器。
// 配置里包含轮次、消息数、字节估计和安全假设，供页面对比展示。
func New() (*Protocol, error) {
	s, err := real.NewRuntime(real.Config{ProtocolName: "GG18", Rounds: 9, Messages: 14, BytesBase: 4200,
		Security: mpcapi.SecurityProfile{Assumption: "离散对数 + Paillier", ThresholdSupport: "t-of-n", NonceRequirement: "强随机nonce与承诺校验"}})
	if err != nil {
		return nil, err
	}
	return &Protocol{s: s}, nil
}
func (p *Protocol) Name() string         { return "GG18" }             // 返回协议名
func (p *Protocol) PublicKeyHex() string { return p.s.PublicKeyHex() } // 返回协议公钥地址
func (p *Protocol) SignTransfer(msg []byte) (mpcapi.Signature, mpcapi.Transcript, error) {
	return p.s.Sign(msg) // 委托共享模拟器执行签名
}
func (p *Protocol) Verify(msg []byte, sig mpcapi.Signature) (bool, error) {
	return p.s.Verify(msg, sig) // 委托共享模拟器执行验签
}
func (p *Protocol) LastMetrics() mpcapi.Metrics   { return p.s.LastMetrics() }           // 返回最近一次签名指标
func (p *Protocol) StaticProfile() mpcapi.Metrics { return p.s.StaticProfile() }         // 返回静态协议画像
func (p *Protocol) EncryptedShareExample() string { return p.s.EncryptedShareExample() } // 返回加密份额示例
