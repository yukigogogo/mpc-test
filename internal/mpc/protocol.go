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

func AvailableProtocols() []string {
	names := []string{"GG18", "GG20", "CGGMP21", "FROST", "EdDSA-TSS"}
	sort.Strings(names)
	return names
}

func NewByName(name string) (mpcapi.Protocol, error) {
	switch name {
	case "GG18":
		return gg18.New()
	case "GG20":
		return gg20.New()
	case "CGGMP21":
		return cggmp21.New()
	case "FROST":
		return frost.New()
	case "EdDSA-TSS":
		return eddsatss.New()
	default:
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}
