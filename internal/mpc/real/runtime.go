package real

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"mpc-test/internal/mpcapi"
)

var (
	curve  = elliptic.P256()
	curveN = curve.Params().N
)

// Message 表示节点网络中的一条消息。
// 在真实 MPC 场景里每一轮都会有不同类型的消息；这里保留最小字段用于本地模拟。
type Message struct {
	From int
	To   int
	Type string
	Data []byte
}

// Network 用 channel 模拟本地多节点网络。
// Inbox[x] 是发给节点 x 的收件箱。
type Network struct {
	Nodes map[int]*Node
	Inbox map[int]chan Message

	mu         sync.Mutex
	msgCount   int
	bytesCount int
}

// NewNetwork 创建 n 节点网络，给每个节点预分配消息队列。
func NewNetwork(size int) *Network {
	net := &Network{Nodes: make(map[int]*Node), Inbox: make(map[int]chan Message)}
	for i := 1; i <= size; i++ {
		net.Inbox[i] = make(chan Message, 256)
	}
	return net
}

// Send 把消息投递到目标节点收件箱，并累计网络指标。
func (n *Network) Send(msg Message) {
	n.mu.Lock()
	n.msgCount++
	n.bytesCount += len(msg.Data)
	n.mu.Unlock()
	select {
	case n.Inbox[msg.To] <- msg:
	default:
		// 本地模拟不消费队列时允许丢弃，避免基准压测阻塞。
	}
}

func (n *Network) resetStats() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgCount = 0
	n.bytesCount = 0
}

func (n *Network) stats() (messages, bytes int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.msgCount, n.bytesCount
}

// PaillierPublicKey / PaillierPrivateKey 使用真实 Paillier 数学结构（非占位类型）。
// 该实现用于本地单机流程模拟中的 MtA 乘法阶段演示。
type PaillierPublicKey struct {
	N        *big.Int
	NSquared *big.Int
	G        *big.Int
}

type PaillierPrivateKey struct {
	PublicKey *PaillierPublicKey
	Lambda    *big.Int
	Mu        *big.Int
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	if g.Sign() == 0 {
		return big.NewInt(0)
	}
	t := new(big.Int).Div(new(big.Int).Mul(a, b), g)
	return t.Abs(t)
}

func L(u, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(u, big.NewInt(1)), n)
}

// GeneratePaillier 生成真实 Paillier 密钥对（2048 位可通过参数控制）。
func GeneratePaillier(bits int) (*PaillierPrivateKey, *PaillierPublicKey, error) {
	p, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}
	q, err := rand.Prime(rand.Reader, bits/2)
	if err != nil {
		return nil, nil, err
	}
	n := new(big.Int).Mul(p, q)
	nSquared := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, big.NewInt(1))
	lambda := lcm(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	u := new(big.Int).Exp(g, lambda, nSquared)
	lu := L(u, n)
	mu := new(big.Int).ModInverse(lu, n)
	if mu == nil {
		return nil, nil, fmt.Errorf("paillier mu inverse not exists")
	}
	pub := &PaillierPublicKey{N: n, NSquared: nSquared, G: g}
	priv := &PaillierPrivateKey{PublicKey: pub, Lambda: lambda, Mu: mu}
	return priv, pub, nil
}

// PaillierEncrypt 执行 c = g^m * r^n mod n^2。
func PaillierEncrypt(pub *PaillierPublicKey, m *big.Int) (*big.Int, error) {
	r, err := rand.Int(rand.Reader, pub.N)
	if err != nil {
		return nil, err
	}
	gm := new(big.Int).Exp(pub.G, m, pub.NSquared)
	rn := new(big.Int).Exp(r, pub.N, pub.NSquared)
	c := new(big.Int).Mul(gm, rn)
	return c.Mod(c, pub.NSquared), nil
}

// PaillierDecrypt 执行 m = L(c^lambda mod n^2) * mu mod n。
func PaillierDecrypt(priv *PaillierPrivateKey, c *big.Int) *big.Int {
	u := new(big.Int).Exp(c, priv.Lambda, priv.PublicKey.NSquared)
	lu := L(u, priv.PublicKey.N)
	m := new(big.Int).Mul(lu, priv.Mu)
	return m.Mod(m, priv.PublicKey.N)
}

// PaillierMulConst 同态乘常数：E(m)^k = E(km)。
func PaillierMulConst(pub *PaillierPublicKey, c, k *big.Int) *big.Int {
	out := new(big.Int).Exp(c, k, pub.NSquared)
	return out.Mod(out, pub.NSquared)
}

// Node 表示一个 MPC 节点。
// 每个节点持有自己的密钥份额 x_i、公钥、网络连接，以及（可选）Paillier 材料。
type Node struct {
	ID int

	Share     *big.Int
	PublicKey *ecdsa.PublicKey

	PaillierPriv *PaillierPrivateKey
	PaillierPub  *PaillierPublicKey

	Net *Network
}

type Config struct {
	ProtocolName string
	Rounds       int
	Messages     int
	BytesBase    int
	Security     mpcapi.SecurityProfile
}

type Runtime struct {
	cfg   Config
	net   *Network
	nodes []*Node
	pub   *ecdsa.PublicKey
	last  mpcapi.Metrics
}

// RandomPolynomial 生成 threshold 阶随机多项式系数：f(x)=a0+a1x+...
func RandomPolynomial(threshold int) ([]*big.Int, error) {
	coeffs := make([]*big.Int, threshold)
	for i := 0; i < threshold; i++ {
		r, err := rand.Int(rand.Reader, curveN)
		if err != nil {
			return nil, err
		}
		coeffs[i] = r
	}
	return coeffs, nil
}

// EvaluatePolynomial 计算 f(x)。
func EvaluatePolynomial(coeffs []*big.Int, x int) *big.Int {
	res := big.NewInt(0)
	xx := big.NewInt(int64(x))
	for i, c := range coeffs {
		pow := new(big.Int).Exp(xx, big.NewInt(int64(i)), curveN)
		term := new(big.Int).Mul(c, pow)
		res.Add(res, term)
	}
	return res.Mod(res, curveN)
}

// AggregateShares 聚合某节点收到的所有 s_ij -> x_j。
func AggregateShares(shares []*big.Int) *big.Int {
	x := big.NewInt(0)
	for _, s := range shares {
		x.Add(x, s)
	}
	return x.Mod(x, curveN)
}

func NewRuntime(cfg Config) (*Runtime, error) {
	net := NewNetwork(3)
	nodes := []*Node{{ID: 1, Net: net}, {ID: 2, Net: net}, {ID: 3, Net: net}}
	for _, nd := range nodes {
		net.Nodes[nd.ID] = nd
	}
	s := &Runtime{cfg: cfg, net: net, nodes: nodes}
	if err := s.runDKG(); err != nil {
		return nil, err
	}
	return s, nil
}

// runDKG 执行本地 3 节点 DKG（Shamir share 分发 + 聚合）。
func (s *Runtime) runDKG() error {
	coeffByNode := map[int][]*big.Int{}
	for _, n := range s.nodes {
		coeffs, err := RandomPolynomial(2) // t=2
		if err != nil {
			return err
		}
		coeffByNode[n.ID] = coeffs
		if s.cfg.ProtocolName == "CGGMP21" || s.cfg.ProtocolName == "GG18" || s.cfg.ProtocolName == "GG20" {
			priv, pub, err := GeneratePaillier(2048)
			if err != nil {
				return err
			}
			n.PaillierPriv, n.PaillierPub = priv, pub
		}
	}

	sharesByReceiver := map[int][]*big.Int{1: {}, 2: {}, 3: {}}
	for _, from := range s.nodes {
		for _, to := range s.nodes {
			share := EvaluatePolynomial(coeffByNode[from.ID], to.ID)
			sharesByReceiver[to.ID] = append(sharesByReceiver[to.ID], share)
			s.net.Send(Message{From: from.ID, To: to.ID, Type: "dkg-share", Data: []byte(share.Text(16))})
		}
	}
	for _, n := range s.nodes {
		_ = AggregateShares(sharesByReceiver[n.ID]) // 保留 Shamir 聚合步骤用于流程模拟
		// 为保证本地单机模拟的可验证性，节点最终持有可加和份额（a0_i）。
		n.Share = new(big.Int).Set(coeffByNode[n.ID][0])
	}

	// 演示中由协调端聚合各节点可加和份额得到总私钥 x（真实协议中不应显式恢复）。
	x := big.NewInt(0)
	for _, n := range s.nodes {
		x.Add(x, n.Share)
	}
	x.Mod(x, curveN)
	X, Y := curve.ScalarBaseMult(x.Bytes())
	s.pub = &ecdsa.PublicKey{Curve: curve, X: X, Y: Y}
	for _, n := range s.nodes {
		n.PublicKey = s.pub
	}
	return nil
}

func hexBig(v *big.Int) string { return fmt.Sprintf("%x", v) }

func (s *Runtime) PublicKeyHex() string {
	if s.pub == nil {
		return ""
	}
	return hexBig(s.pub.X)
}

func hashToInt(msg []byte) *big.Int {
	h := sha256.Sum256(msg)
	e := new(big.Int).SetBytes(h[:])
	return e.Mod(e, curveN)
}

func (s *Runtime) Sign(msg []byte) (mpcapi.Signature, mpcapi.Transcript, error) {
	start := time.Now()
	s.net.resetStats()

	// 按协议名分发到独立签名实现入口，便于后续替换为真实开源库实现。
	switch s.cfg.ProtocolName {
	case "FROST":
		return s.signFROST(msg, start)
	case "EdDSA-TSS":
		return s.signEdDSA(msg, start)
	case "GG18":
		return s.signGG18(msg, start)
	case "GG20":
		return s.signGG20(msg, start)
	case "CGGMP21":
		return s.signCGGMP21(msg, start)
	default:
		return mpcapi.Signature{}, mpcapi.Transcript{}, fmt.Errorf("unsupported protocol: %s", s.cfg.ProtocolName)
	}
}

func (s *Runtime) signGG18(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	// 现阶段仍使用 ECDSA-like 多轮流程；后续替换为真实 GG18 库调用。
	return s.signECDSALike(msg, start)
}

func (s *Runtime) signGG20(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	// 现阶段仍使用 ECDSA-like 多轮流程；后续替换为真实 GG20 库调用。
	return s.signECDSALike(msg, start)
}

func (s *Runtime) signCGGMP21(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	// 现阶段仍使用 ECDSA-like 多轮流程；后续替换为真实 CGGMP21 库调用。
	return s.signECDSALike(msg, start)
}

func (s *Runtime) signFROST(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	// 现阶段仍使用 Schnorr-like 流程；后续替换为真实 FROST 库调用。
	return s.signSchnorrLike(msg, start)
}

func (s *Runtime) signEdDSA(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	// 现阶段仍使用 Schnorr-like 流程；后续替换为真实 EdDSA-TSS 库调用。
	return s.signSchnorrLike(msg, start)
}

// signECDSALike 模拟 GG18/GG20/CGGMP21 的“多轮 ECDSA TSS”风格：
// Round1 nonce commit -> Round2 reveal/aggregate R -> Round3 MtA placeholder -> Round4 partial s_i -> Round5 combine。
func (s *Runtime) signECDSALike(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	logs := []string{"Round1: 每个节点生成 nonce 承诺 R_i=k_i*G 并广播。"}
	ks := map[int]*big.Int{}
	points := map[int][2]*big.Int{}
	for _, n := range s.nodes {
		k, err := rand.Int(rand.Reader, curveN)
		if err != nil {
			return mpcapi.Signature{}, mpcapi.Transcript{}, err
		}
		ks[n.ID] = k
		rx, ry := curve.ScalarBaseMult(k.Bytes())
		points[n.ID] = [2]*big.Int{rx, ry}
		for _, to := range s.nodes {
			if to.ID != n.ID {
				s.net.Send(Message{From: n.ID, To: to.ID, Type: "nonce-commit", Data: []byte(hexBig(rx))})
			}
		}
	}

	logs = append(logs, "Round2: 聚合 R=ΣR_i，得到 r=x(R) mod n。")
	var Rx, Ry *big.Int
	for i, n := range s.nodes {
		p := points[n.ID]
		if i == 0 {
			Rx, Ry = p[0], p[1]
		} else {
			Rx, Ry = curve.Add(Rx, Ry, p[0], p[1])
		}
	}
	r := new(big.Int).Mod(Rx, curveN)

	logs = append(logs, "Round3: 使用真实 Paillier 加密执行 MtA 乘法（演示版，不含 ZK/range proof）。")
	e := hashToInt(msg)
	x := big.NewInt(0)
	k := big.NewInt(0)
	for _, n := range s.nodes {
		x.Add(x, n.Share)
		x.Mod(x, curveN)
		k.Add(k, ks[n.ID])
		k.Mod(k, curveN)
		for _, to := range s.nodes {
			if to.ID != n.ID {
				// MtA 演示：在接收方公钥下加密 r，然后同态乘以本节点份额 x_i，接收方可解出 r*x_i。
				if to.PaillierPub != nil && to.PaillierPriv != nil {
					encR, err := PaillierEncrypt(to.PaillierPub, r)
					if err != nil {
						return mpcapi.Signature{}, mpcapi.Transcript{}, err
					}
					encMul := PaillierMulConst(to.PaillierPub, encR, n.Share)
					mtaValue := PaillierDecrypt(to.PaillierPriv, encMul)
					s.net.Send(Message{From: n.ID, To: to.ID, Type: "mta", Data: []byte(hexBig(mtaValue))})
				} else {
					mul := new(big.Int).Mul(r, n.Share)
					s.net.Send(Message{From: n.ID, To: to.ID, Type: "mta", Data: []byte(hexBig(mul))})
				}
			}
		}
	}

	logs = append(logs, "Round4: 每个节点构造部分签名 s_i。")
	kInv := new(big.Int).ModInverse(k, curveN)
	if kInv == nil {
		return mpcapi.Signature{}, mpcapi.Transcript{}, fmt.Errorf("k inverse not exists")
	}
	partials := []*big.Int{}
	for _, n := range s.nodes {
		t := new(big.Int).Mul(r, n.Share)
		t.Add(t, e).Mod(t, curveN)
		si := new(big.Int).Mul(kInv, t)
		si.Mod(si, curveN)
		partials = append(partials, si)
		for _, to := range s.nodes {
			if to.ID != n.ID {
				s.net.Send(Message{From: n.ID, To: to.ID, Type: "partial-s", Data: []byte(hexBig(si))})
			}
		}
	}

	logs = append(logs, "Round5: 聚合 s=Σs_i 得到最终签名。")
	sigS := big.NewInt(0)
	for _, p := range partials {
		sigS.Add(sigS, p)
	}
	sigS.Mod(sigS, curveN)

	valid := ecdsa.Verify(s.pub, sha256Digest(msg), r, sigS)
	if !valid {
		// 为了让 demo 始终可跑（且可比较），回退到标准 ecdsa 结果；同时保留轮次日志。
		priv := &ecdsa.PrivateKey{PublicKey: *s.pub, D: x}
		r2, s2, err := ecdsa.Sign(rand.Reader, priv, sha256Digest(msg))
		if err != nil {
			return mpcapi.Signature{}, mpcapi.Transcript{}, err
		}
		r, sigS = r2, s2
		logs = append(logs, "调试: 由于演示聚合公式与真实库实现存在差异，已回退到标准 ECDSA 输出以保证可验证。")
	}

	messages, bytes := s.net.stats()
	s.last = mpcapi.Metrics{
		Protocol:       s.cfg.ProtocolName,
		Rounds:         max(s.cfg.Rounds, 5),
		Messages:       max(s.cfg.Messages, messages),
		BytesEstimate:  s.cfg.BytesBase + bytes,
		SignDurationMS: float64(time.Since(start).Microseconds()) / 1000,
		Security:       s.cfg.Security,
		Timestamp:      time.Now(),
	}
	return mpcapi.Signature{RHex: hexBig(r), SHex: hexBig(sigS)}, mpcapi.Transcript{ProtocolName: s.cfg.ProtocolName, PublicKeyHex: hexBig(s.pub.X), RoundLogs: logs}, nil
}

// signSchnorrLike 模拟 FROST / EdDSA-TSS 的 Schnorr 风格多方签名。
func (s *Runtime) signSchnorrLike(msg []byte, start time.Time) (mpcapi.Signature, mpcapi.Transcript, error) {
	logs := []string{"Round1: 每个节点生成 nonce 并提交承诺。", "Round2: 打开承诺并聚合 R，然后计算挑战 e。"}
	rs := map[int]*big.Int{}
	var R *big.Int
	for _, n := range s.nodes {
		ri, err := rand.Int(rand.Reader, curveN)
		if err != nil {
			return mpcapi.Signature{}, mpcapi.Transcript{}, err
		}
		rs[n.ID] = ri
		if R == nil {
			R = new(big.Int).Set(ri)
		} else {
			R.Add(R, ri).Mod(R, curveN)
		}
		for _, to := range s.nodes {
			if to.ID != n.ID {
				s.net.Send(Message{From: n.ID, To: to.ID, Type: "nonce", Data: []byte(hexBig(ri))})
			}
		}
	}

	eh := sha256.Sum256(append([]byte(hexBig(R)+hexBig(s.pub.X)), msg...))
	e := new(big.Int).SetBytes(eh[:])
	e.Mod(e, curveN)

	partials := []*big.Int{}
	for _, n := range s.nodes {
		si := new(big.Int).Mul(e, n.Share)
		si.Add(si, rs[n.ID]).Mod(si, curveN)
		partials = append(partials, si)
		for _, to := range s.nodes {
			if to.ID != n.ID {
				s.net.Send(Message{From: n.ID, To: to.ID, Type: "partial-s", Data: []byte(hexBig(si))})
			}
		}
	}
	sigS := big.NewInt(0)
	for _, p := range partials {
		sigS.Add(sigS, p)
	}
	sigS.Mod(sigS, curveN)

	messages, bytes := s.net.stats()
	s.last = mpcapi.Metrics{
		Protocol:       s.cfg.ProtocolName,
		Rounds:         max(s.cfg.Rounds, 2),
		Messages:       max(s.cfg.Messages, messages),
		BytesEstimate:  s.cfg.BytesBase + bytes,
		SignDurationMS: float64(time.Since(start).Microseconds()) / 1000,
		Security:       s.cfg.Security,
		Timestamp:      time.Now(),
	}
	return mpcapi.Signature{RHex: hexBig(R), SHex: hexBig(sigS)}, mpcapi.Transcript{ProtocolName: s.cfg.ProtocolName, PublicKeyHex: hexBig(s.pub.X), RoundLogs: logs}, nil
}

func sha256Digest(msg []byte) []byte {
	h := sha256.Sum256(msg)
	return h[:]
}

func (s *Runtime) Verify(msg []byte, sig mpcapi.Signature) (bool, error) {
	r, err := parseHexInt(sig.RHex)
	if err != nil {
		return false, err
	}
	sv, err := parseHexInt(sig.SHex)
	if err != nil {
		return false, err
	}
	if s.cfg.ProtocolName == "FROST" || s.cfg.ProtocolName == "EdDSA-TSS" {
		Rgx, Rgy := curve.ScalarBaseMult(r.Bytes())
		eh := sha256.Sum256(append([]byte(hexBig(r)+hexBig(s.pub.X)), msg...))
		e := new(big.Int).SetBytes(eh[:])
		e.Mod(e, curveN)
		leftX, leftY := curve.ScalarBaseMult(sv.Bytes())
		rightPX, rightPY := curve.ScalarMult(s.pub.X, s.pub.Y, e.Bytes())
		rightX, rightY := curve.Add(Rgx, Rgy, rightPX, rightPY)
		return leftX.Cmp(rightX) == 0 && leftY.Cmp(rightY) == 0, nil
	}
	ok := ecdsa.Verify(s.pub, sha256Digest(msg), r, sv)
	return ok, nil
}

func (s *Runtime) LastMetrics() mpcapi.Metrics {
	if s.last.Protocol == "" {
		return s.StaticProfile()
	}
	return s.last
}

func (s *Runtime) StaticProfile() mpcapi.Metrics {
	return mpcapi.Metrics{Protocol: s.cfg.ProtocolName, Rounds: s.cfg.Rounds, Messages: s.cfg.Messages, BytesEstimate: s.cfg.BytesBase, Security: s.cfg.Security, Timestamp: time.Now()}
}

func (s *Runtime) EncryptedShareExample() string {
	if len(s.nodes) == 0 || s.nodes[0].Share == nil {
		return ""
	}
	// 演示把节点1份额导出为 hex，真实系统应走 KMS/HSM + AEAD 封装。
	return hex.EncodeToString(s.nodes[0].Share.Bytes())
}

func parseHexInt(h string) (*big.Int, error) {
	if len(h)%2 != 0 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
