package mpc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// 演示用 2048-bit MODP group (RFC3526 group14)；仅用于 demo。
const primeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
	"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD" +
	"3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E" +
	"7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F" +
	"A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C" +
	"62F356208552BB9ED529077096966D670C354E4ABC9804F174" +
	"6C08CA18217C32905E462E36CE3BE39E772C180E86039B2783" +
	"A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C" +
	"EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

var (
	modP = mustBig(primeHex)
	q    = new(big.Int).Rsh(new(big.Int).Sub(modP, big.NewInt(1)), 1) // subgroup order
	g    = big.NewInt(2)
)

func mustBig(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("invalid prime")
	}
	return v
}

type Signature struct {
	RHex string `json:"R"`
	SHex string `json:"s"`
}

type Transcript struct {
	PublicKeyHex string   `json:"publicKey"`
	RoundLogs    []string `json:"roundLogs"`
}

type party struct{ share *big.Int }

type Protocol struct {
	p1 party
	p2 party
}

func randomScalar() (*big.Int, error) {
	for {
		x, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		if x.Sign() > 0 {
			return x, nil
		}
	}
}

func NewProtocol() (*Protocol, error) {
	s1, err := randomScalar()
	if err != nil {
		return nil, err
	}
	s2, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return &Protocol{p1: party{s1}, p2: party{s2}}, nil
}

func hexBig(v *big.Int) string { return fmt.Sprintf("%x", v) }

func (p *Protocol) pubKey() *big.Int {
	x := new(big.Int).Add(p.p1.share, p.p2.share)
	x.Mod(x, q)
	return new(big.Int).Exp(g, x, modP)
}

func (p *Protocol) PublicKeyHex() string { return hexBig(p.pubKey()) }

func challenge(R, P *big.Int, msg []byte) *big.Int {
	h := sha256.New()
	h.Write([]byte(hexBig(R)))
	h.Write([]byte(hexBig(P)))
	h.Write(msg)
	e := new(big.Int).SetBytes(h.Sum(nil))
	e.Mod(e, q)
	return e
}

func (p *Protocol) SignTransfer(msg []byte) (Signature, Transcript, error) {
	logs := []string{"Round1: 两个参与方独立生成随机nonce"}
	r1, err := randomScalar()
	if err != nil {
		return Signature{}, Transcript{}, err
	}
	r2, err := randomScalar()
	if err != nil {
		return Signature{}, Transcript{}, err
	}
	R1 := new(big.Int).Exp(g, r1, modP)
	R2 := new(big.Int).Exp(g, r2, modP)
	R := new(big.Int).Mul(R1, R2)
	R.Mod(R, modP)

	P := p.pubKey()
	e := challenge(R, P, msg)

	s1 := new(big.Int).Mul(e, p.p1.share)
	s1.Add(s1, r1).Mod(s1, q)
	s2 := new(big.Int).Mul(e, p.p2.share)
	s2.Add(s2, r2).Mod(s2, q)
	s := new(big.Int).Add(s1, s2)
	s.Mod(s, q)

	logs = append(logs,
		fmt.Sprintf("- P1公布 R1=%s", hexBig(R1)),
		fmt.Sprintf("- P2公布 R2=%s", hexBig(R2)),
		"Round2: 协调者聚合nonce并计算挑战e=H(R||P||m)",
		fmt.Sprintf("Round3: P1计算部分签名 s1=%s", hexBig(s1)),
		fmt.Sprintf("Round4: P2计算部分签名 s2=%s", hexBig(s2)),
		"Round5: 聚合得到最终签名(s, R)",
	)

	return Signature{RHex: hexBig(R), SHex: hexBig(s)}, Transcript{PublicKeyHex: hexBig(P), RoundLogs: logs}, nil
}

func parseHexInt(h string) (*big.Int, error) {
	b, err := hex.DecodeString(padEven(h))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func padEven(h string) string {
	if len(h)%2 == 0 {
		return h
	}
	return "0" + h
}

// Verify checks g^s == R * P^e mod p.
func Verify(msg []byte, pubKeyHex string, sig Signature) (bool, error) {
	R, err := parseHexInt(sig.RHex)
	if err != nil {
		return false, err
	}
	S, err := parseHexInt(sig.SHex)
	if err != nil {
		return false, err
	}
	P, err := parseHexInt(pubKeyHex)
	if err != nil {
		return false, err
	}
	e := challenge(R, P, msg)
	left := new(big.Int).Exp(g, S, modP)
	right := new(big.Int).Exp(P, e, modP)
	right.Mul(right, R).Mod(right, modP)
	return left.Cmp(right) == 0, nil
}
