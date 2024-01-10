//go:build ignore

package metrics

import "github.com/coredns/caddy"

func listPlugins() map[string][]string {
	return caddy.ListPlugins()
}
