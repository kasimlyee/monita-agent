// Package fingerprint computes a stable hardware identity hash for the host.
// The hash is SHA-256(machine_id + primary_mac + root_volume_uuid).
// Raw component values never leave the host; only the hash is sent to the Collector.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// Compute returns the hex-encoded SHA-256 fingerprint hash.
// Missing components are logged to stderr and treated as empty strings; partial
// fingerprints are still registered so the Collector can surface drift warnings.
func Compute() (string, error) {
	mid, err := machineID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=warn msg=\"fingerprint: machine_id unavailable\" err=%q\n", err)
		mid = ""
	}

	mac, err := primaryMAC()
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=warn msg=\"fingerprint: primary_mac unavailable\" err=%q\n", err)
		mac = ""
	}

	uuid, err := rootVolumeUUID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "level=warn msg=\"fingerprint: root_volume_uuid unavailable\" err=%q\n", err)
		uuid = ""
	}

	if mid == "" && mac == "" && uuid == "" {
		return "", fmt.Errorf("all fingerprint components unavailable; cannot identify host")
	}

	h := sha256.Sum256([]byte(mid + mac + uuid))
	return hex.EncodeToString(h[:]), nil
}

// primaryMAC returns the hardware address of the first non-loopback, up interface
// with a real MAC address. Interfaces are iterated in index order so the result
// is stable across reboots on the same hardware.
func primaryMAC() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		// Skip virtual/docker bridge interfaces whose MACs change between deploys.
		name := strings.ToLower(iface.Name)
		if strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
			continue
		}
		return iface.HardwareAddr.String(), nil
	}
	return "", fmt.Errorf("no suitable network interface found")
}