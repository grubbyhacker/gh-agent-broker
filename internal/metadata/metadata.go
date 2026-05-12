// Package metadata enriches and renders broker metadata blocks.
package metadata

import (
	"fmt"
	"sort"
	"strings"
)

func WithBrokerFields(in map[string]string, agentID, operationID string, installationID int64) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	if agentID != "" {
		out["Agent-Id"] = agentID
	}
	if operationID != "" {
		out["Broker-Operation-Id"] = operationID
	}
	if installationID != 0 {
		out["GitHub-App-Installation-Id"] = fmt.Sprintf("%d", installationID)
	}
	return out
}

func RenderBlock(values map[string]string) string {
	if len(values) == 0 {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("\n\n<!-- gh-agent-broker:metadata\n")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(values[k])
		b.WriteByte('\n')
	}
	b.WriteString("-->\n")
	return b.String()
}
