package cggmp21

import (
	"mpc-test/internal/mpc/sim"
	"mpc-test/internal/mpcapi"
)

type Protocol struct{ s *sim.Simulator }

func New() (*Protocol, error) {
	s, err := sim.NewSimulator(sim.Config{ProtocolName: "CGGMP21", Rounds: 6, Messages: 8, BytesBase: 3000,
		Security: mpcapi.SecurityProfile{Assumption: "离散对数 + UC安全证明", ThresholdSupport: "t-of-n", NonceRequirement: "并发场景下必须唯一nonce"}})
	if err != nil {
		return nil, err
	}
	return &Protocol{s: s}, nil
}
func (p *Protocol) Name() string         { return "CGGMP21" }
func (p *Protocol) PublicKeyHex() string { return p.s.PublicKeyHex() }
func (p *Protocol) SignTransfer(msg []byte) (mpcapi.Signature, mpcapi.Transcript, error) {
	return p.s.Sign(msg)
}
func (p *Protocol) Verify(msg []byte, sig mpcapi.Signature) (bool, error) {
	return p.s.Verify(msg, sig)
}
func (p *Protocol) LastMetrics() mpcapi.Metrics   { return p.s.LastMetrics() }
func (p *Protocol) StaticProfile() mpcapi.Metrics { return p.s.StaticProfile() }
func (p *Protocol) EncryptedShareExample() string { return p.s.EncryptedShareExample() }
