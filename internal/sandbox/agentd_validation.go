package sandbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

func deriveAgentdValidationToken(secret, workerID, storageLineageID string, fenceEpoch int64) string {
	payload, err := json.Marshal(struct {
		Domain           string `json:"domain"`
		WorkerID         string `json:"worker_id"`
		StorageLineageID string `json:"storage_lineage_id"`
		FenceEpoch       int64  `json:"fence_epoch"`
	}{
		Domain:           "gh-agent-broker/agentd-validation/v1",
		WorkerID:         workerID,
		StorageLineageID: storageLineageID,
		FenceEpoch:       fenceEpoch,
	})
	if err != nil {
		panic("marshal agentd validation token payload: " + err.Error())
	}
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write(payload); err != nil {
		panic("hash agentd validation token payload: " + err.Error())
	}
	return "av1." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
