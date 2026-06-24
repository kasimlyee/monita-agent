//go:build !linux

package fingerprint

import "fmt"

func machineID() (string, error) {
	return "", fmt.Errorf("machineID not implemented on this platform")
}

func rootVolumeUUID() (string, error) {
	return "", fmt.Errorf("rootVolumeUUID not implemented on this platform")
}