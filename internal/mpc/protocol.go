package mpc

import (
	"fmt"
	"sort"

	"mpc-test/internal/mpcapi"

	"mpc-test/internal/mpc/protocols/cggmp21"
	"mpc-test/internal/mpc/protocols/eddsatss"
	"mpc-test/internal/mpc/protocols/frost"
	"mpc-test/internal/mpc/protocols/gg18"
	"mpc-test/internal/mpc/protocols/gg20"
)


// AvailableProtocols 返回当前系统支持的协议名称列表。
//
// 为什么要统一在这里维护：
// 1) 前端协议下拉框需要这份列表。
// 2) 钱包服务初始化协议实例时需要遍历这份列表。
// 3) benchmark 需要稳定顺序，便于横向比较输出。
func AvailableProtocols() []string {
	// 先声明原始协议集合。
	names := []string{"GG18", "GG20", "CGGMP21", "FROST", "EdDSA-TSS"}
	// 统一排序，避免 map 遍历顺序不稳定导致页面展示顺序抖动。
	sort.Strings(names)
	// 返回排序后的协议名切片。
	return names
}

// NewByName 根据协议名创建对应协议实例。
//
// 这里使用工厂模式：上层只需要传字符串，不依赖具体实现包。
// 好处是新增协议时，只需要在本文件新增 case 分支。
func NewByName(name string) (mpcapi.Protocol, error) {
	switch name {
	case "GG18":
		// 创建 GG18 协议实例。
		return gg18.New()
	case "GG20":
		// 创建 GG20 协议实例。
		return gg20.New()
	case "CGGMP21":
		// 创建 CGGMP21 协议实例。
		return cggmp21.New()
	case "FROST":
		// 创建 FROST 协议实例。
		return frost.New()
	case "EdDSA-TSS":
		// 创建 EdDSA-TSS 协议实例。
		return eddsatss.New()
	default:
		// 未知协议直接返回错误，避免后续空指针问题。
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}
