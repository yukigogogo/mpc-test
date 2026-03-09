package mpcapi

import "time"

// Signature 表示统一的签名结果结构。
// 不同协议可以将自己协议中的核心字段映射到这两个字符串字段，
// 方便前端统一展示、后端统一校验。
type Signature struct {
	RHex string `json:"R"`
	SHex string `json:"s"`
}

// Transcript 记录一次签名过程中每一轮发生了什么，
// 便于在页面中直观看到协议流程差异。
type Transcript struct {
	ProtocolName string   `json:"protocolName"`
	PublicKeyHex string   `json:"publicKey"`
	RoundLogs    []string `json:"roundLogs"`
}

// SecurityProfile 用于把“安全性”维度结构化输出，便于对比。
type SecurityProfile struct {
	Assumption       string `json:"assumption"`
	ThresholdSupport string `json:"thresholdSupport"`
	NonceRequirement string `json:"nonceRequirement"`
}

// Metrics 记录一次签名的关键指标，
// 用于“性能 / 网络 / 安全”三个维度的可视化对比。
type Metrics struct {
	Protocol       string          `json:"protocol"`
	Rounds         int             `json:"rounds"`
	Messages       int             `json:"messages"`
	BytesEstimate  int             `json:"bytesEstimate"`
	SignDurationMS float64         `json:"signDurationMs"`
	Security       SecurityProfile `json:"security"`
	Timestamp      time.Time       `json:"timestamp"`
}

// Protocol 定义各协议最小统一能力：
// 1) 返回协议名
// 2) 返回公钥
// 3) 对消息进行门限签名
// 4) 校验签名
// 5) 返回最近一次签名指标
// 6) 返回该协议的静态指标画像
// 7) 导出“密钥加密存储”示例（便于教学）
type Protocol interface {
	Name() string
	PublicKeyHex() string
	SignTransfer(msg []byte) (Signature, Transcript, error)
	Verify(msg []byte, sig Signature) (bool, error)
	LastMetrics() Metrics
	StaticProfile() Metrics
	EncryptedShareExample() string
}
