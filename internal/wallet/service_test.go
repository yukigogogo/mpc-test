package wallet

import "testing"

func TestTransferUpdatesBalance(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Transfer(TransferRequest{To: "alice", Amount: 25, Protocol: "FROST"})
	if err != nil {
		t.Fatal(err)
	}
	st := svc.GetState()
	if st.Balance != 975 {
		t.Fatalf("want 975 got %d", st.Balance)
	}
	if st.Accounts["alice"] != 25 {
		t.Fatalf("want alice=25 got %d", st.Accounts["alice"])
	}
}

func TestBenchmarkReturnsAllProtocols(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatal(err)
	}
	m := svc.Benchmark()
	if len(m) != 5 {
		t.Fatalf("want 5 protocols got %d", len(m))
	}
}
