package sim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"mpc-test/internal/mpcapi"
)

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
	q    = new(big.Int).Rsh(new(big.Int).Sub(modP, big.NewInt(1)), 1)
	g    = big.NewInt(2)
)

type Config struct {
	ProtocolName string                 // 协议名（用于展示与指标打点）
	Rounds       int                    // 估算签名轮次
	Messages     int                    // 估算消息数
	BytesBase    int                    // 估算固定网络字节开销
	Security     mpcapi.SecurityProfile // 协议安全画像
}

type Simulator struct {
	cfg   Config         // 协议配置
	share *big.Int       // 演示私钥份额
	last  mpcapi.Metrics // 最近一次签名指标
}

func mustBig(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("invalid prime")
	}
	return v
}

func randomScalar() (*big.Int, error) {
	for {
		// 在 [0, q) 中采样随机数。
		x, err := rand.Int(rand.Reader, q)
		if err != nil {
			return nil, err
		}
		// 排除 0，避免生成无效标量。
		if x.Sign() > 0 {
			return x, nil
		}
	}
}

func NewSimulator(cfg Config) (*Simulator, error) {
	// 初始化“本节点密钥份额”，真实 MPC 中该值来自 DKG。
	k, err := randomScalar()
	if err != nil {
		return nil, err
	}
	return &Simulator{cfg: cfg, share: k}, nil
}

func hexBig(v *big.Int) string { return fmt.Sprintf("%x", v) }

func (s *Simulator) PublicKeyHex() string {
	return hexBig(new(big.Int).Exp(g, s.share, modP))
}

func challenge(R, P *big.Int, msg []byte) *big.Int {
	// 构造挑战 e = H(R || P || msg)。
	h := sha256.New()
	h.Write([]byte(hexBig(R)))
	h.Write([]byte(hexBig(P)))
	h.Write(msg)
	e := new(big.Int).SetBytes(h.Sum(nil))
	// 将哈希映射到群阶 q。
	e.Mod(e, q)
	return e
}

// Sign 用“可验证的 Schnorr 风格流程 + 可配置轮次指标”模拟不同协议。
// 注意：这里是教学型 demo，不是生产级协议实现。
func (s *Simulator) Sign(msg []byte) (mpcapi.Signature, mpcapi.Transcript, error) {
	start := time.Now()
	logs := []string{
		"第1步: 读取本地加密密钥份额并解密为会话可用份额。",
		"第2步: 每个参与方生成一次性随机 nonce，防止重放与私钥泄漏。",
	}

	r, err := randomScalar()
	if err != nil {
		return mpcapi.Signature{}, mpcapi.Transcript{}, err
	}
	// 计算承诺点 R = g^r。
	R := new(big.Int).Exp(g, r, modP)
	// 计算公钥 P = g^x（x 为 share）。
	P := new(big.Int).Exp(g, s.share, modP)
	// 计算挑战值 e。
	e := challenge(R, P, msg)
	// 计算 s = r + e*x (mod q)。
	sigS := new(big.Int).Mul(e, s.share)
	sigS.Add(sigS, r).Mod(sigS, q)

	// 按协议配置写入“额外轮次”日志，模拟不同协议复杂度差异。
	for i := 3; i <= s.cfg.Rounds; i++ {
		logs = append(logs, fmt.Sprintf("第%d步: 协议执行第%d轮消息交换，用于一致性检查与份额聚合。", i, i-2))
	}
	logs = append(logs,
		"最后一步: 协调器聚合部分签名，生成最终签名 (R,s)。",
		fmt.Sprintf("调试信息: R=%s", hexBig(R)),
		fmt.Sprintf("调试信息: s=%s", hexBig(sigS)),
	)

	// 记录本次签名指标供 Benchmark / 页面展示。
	s.last = mpcapi.Metrics{
		Protocol:       s.cfg.ProtocolName,
		Rounds:         s.cfg.Rounds,
		Messages:       s.cfg.Messages,
		BytesEstimate:  s.cfg.BytesBase + len(msg)*s.cfg.Messages,
		SignDurationMS: float64(time.Since(start).Microseconds()) / 1000,
		Security:       s.cfg.Security,
		Timestamp:      time.Now(),
	}
	// 返回统一签名结构和流程日志。
	return mpcapi.Signature{RHex: hexBig(R), SHex: hexBig(sigS)}, mpcapi.Transcript{ProtocolName: s.cfg.ProtocolName, PublicKeyHex: hexBig(P), RoundLogs: logs}, nil
}

func (s *Simulator) Verify(msg []byte, sig mpcapi.Signature) (bool, error) {
	// 解析签名 R 分量。
	R, err := parseHexInt(sig.RHex)
	if err != nil {
		return false, err
	}
	// 解析签名 s 分量。
	S, err := parseHexInt(sig.SHex)
	if err != nil {
		return false, err
	}
	// 解析公钥 P。
	P, err := parseHexInt(s.PublicKeyHex())
	if err != nil {
		return false, err
	}
	// 计算挑战 e = H(R || P || msg)。
	e := challenge(R, P, msg)
	// 左边：g^s。
	left := new(big.Int).Exp(g, S, modP)
	// 右边：R * P^e。
	right := new(big.Int).Exp(P, e, modP)
	right.Mul(right, R).Mod(right, modP)
	// 对比两边是否相等。
	return left.Cmp(right) == 0, nil
}

func (s *Simulator) LastMetrics() mpcapi.Metrics {
	if s.last.Protocol == "" {
		return s.StaticProfile()
	}
	return s.last
}

func (s *Simulator) StaticProfile() mpcapi.Metrics {
	// 当没有最新签名时返回配置层面的静态画像。
	return mpcapi.Metrics{Protocol: s.cfg.ProtocolName, Rounds: s.cfg.Rounds, Messages: s.cfg.Messages, BytesEstimate: s.cfg.BytesBase, Security: s.cfg.Security, Timestamp: time.Now()}
}

// EncryptedShareExample 展示“如何把密钥份额加密后保存”。
// 这里使用 AES-GCM：
// 1) 先从协议名派生演示密钥（真实系统应该来自 KMS/HSM）
// 2) 再用随机 nonce 加密 share
// 3) 输出 nonce+ciphertext，供前端展示。
func (s *Simulator) EncryptedShareExample() string {
	rawShare := s.share.Bytes()
	key := sha256.Sum256([]byte("demo-kms-" + s.cfg.ProtocolName))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "cipher-init-error"
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "gcm-init-error"
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "nonce-error"
	}
	sealed := aead.Seal(nil, nonce, rawShare, nil)
	out := append(nonce, sealed...)
	return hex.EncodeToString(out)
}

func parseHexInt(h string) (*big.Int, error) {
	// hex.DecodeString 需要偶数字符长度，不足时左补 0。
	if len(h)%2 != 0 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
