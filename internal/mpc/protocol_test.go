package mpc

import "testing"

func TestAllProtocolsSignAndVerify(t *testing.T) {
	// 遍历所有协议，确保每个协议都至少能完成一轮签名与验签闭环。
	for _, name := range AvailableProtocols() {
		// 通过工厂创建协议实例。
		p, err := NewByName(name)
		if err != nil {
			t.Fatalf("new protocol %s: %v", name, err)
		}

		// 构造每个协议独有消息，避免测试数据完全重复。
		msg := []byte("transfer-demo-" + name)
		// 执行签名。
		sig, _, err := p.SignTransfer(msg)
		if err != nil {
			t.Fatalf("sign %s: %v", name, err)
		}

		// 执行验签。

		ok, err := p.Verify(msg, sig)
		if err != nil {
			t.Fatalf("verify %s: %v", name, err)
		}

		// 验签必须通过，否则协议实现不正确。

		if !ok {
			t.Fatalf("expected verify ok for %s", name)
		}
	}
}
