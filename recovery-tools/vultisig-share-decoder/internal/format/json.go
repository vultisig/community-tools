package format

import (
	"encoding/json"

	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/internal/recovery"
)

func JSON(r *recovery.RecoveryResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
