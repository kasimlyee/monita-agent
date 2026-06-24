//go:build linux

package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func machineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", fmt.Errorf("read /etc/machine-id: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// rootVolumeUUID resolves the UUID of the device mounted at "/" by walking
// /dev/disk/by-uuid symlinks. We never shell out — pure stdlib fs ops.
func rootVolumeUUID() (string, error) {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("read /proc/mounts: %w", err)
	}

	var rootDev string
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "/" {
			rootDev = fields[0]
			break
		}
	}
	if rootDev == "" {
		return "", fmt.Errorf("root mount not found in /proc/mounts")
	}

	entries, err := os.ReadDir("/dev/disk/by-uuid")
	if err != nil {
		return "", fmt.Errorf("read /dev/disk/by-uuid: %w", err)
	}

	rootBase := filepath.Base(rootDev)
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/dev/disk/by-uuid", e.Name()))
		if err != nil {
			continue
		}
		if filepath.Base(target) == rootBase {
			return e.Name(), nil
		}
	}
	return "", fmt.Errorf("UUID not found for device %s", rootDev)
}
