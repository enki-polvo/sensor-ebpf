// utility/getId.go

package utility

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Returns the username(string) for a given uid(int).
func GetUsername(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return "", fmt.Errorf("user not found for UID %v, %w", uid, err)
	}

	return u.Username, nil
}

// Returns the process name for a given PID,
// by reading the /proc/<PID>/comm file.
func GetProcessName(pid uint32) (string, error) {
	processPath := filepath.Join("/proc", strconv.Itoa(int(pid)), "comm")
	data, err := os.ReadFile(processPath)
	if err != nil {
		return "", fmt.Errorf("failed to read process name for PID %d, %w", pid, err)
	}

	// The /proc/<PID>/comm file contains the process name,
	// but ends with a newline, so trim it.
	return strings.TrimSpace(string(data)), nil
}
