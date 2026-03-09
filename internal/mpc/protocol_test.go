package mpc

import "testing"

func TestAllProtocolsSignAndVerify(t *testing.T) {
	for _, name := range AvailableProtocols() {
		p, err := NewByName(name)
		if err != nil {
			t.Fatalf("new protocol %s: %v", name, err)
		}
		msg := []byte("transfer-demo-" + name)
		sig, _, err := p.SignTransfer(msg)
		if err != nil {
			t.Fatalf("sign %s: %v", name, err)
		}
		ok, err := p.Verify(msg, sig)
		if err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}
		if !ok {
			t.Fatalf("expected verify ok for %s", name)
		}
	}
}
