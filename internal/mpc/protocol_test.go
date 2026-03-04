package mpc

import "testing"

func TestSignAndVerify(t *testing.T) {
	p, err := NewProtocol()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("transfer-demo")
	sig, _, err := p.SignTransfer(msg)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(msg, p.PublicKeyHex(), sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected verify ok")
	}
}
