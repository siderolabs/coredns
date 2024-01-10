//go:build !ignore

package metrics

import (
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/uniq"
)

var (
	log = clog.NewWithPlugin("prometheus")
	u   = uniq.New()
)

func listPlugins() map[string][]string { return map[string][]string{} }
