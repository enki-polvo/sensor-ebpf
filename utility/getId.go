// utility/getId.go

package utility

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	uidUsernameMap map[uint32]string
	initOnce       sync.Once
	initError      error
)

// initUIDMap reads /etc/passwd and populates the uidUsernameMap.
// It's called only once per process lifecycle.
func initUIDMap() {
	uidUsernameMap = make(map[uint32]string)

	file, err := os.Open("/etc/passwd")
	if err != nil {
		initError = fmt.Errorf("failed to open /etc/passwd: %w", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// /etc/passwd format: username:password:UID:GID:... (we only care about username and UID)
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		username := parts[0]
		uidStr := parts[2]
		uid, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			continue
		}
		uidUsernameMap[uint32(uid)] = username
	}

	if err := scanner.Err(); err != nil {
		initError = fmt.Errorf("error reading /etc/passwd: %w", err)
	}
}

// GetUsername returns the username for a given uid.
// It initializes the mapping on the first call.
func GetUsername(uid uint32) (string, error) {
	initOnce.Do(initUIDMap)
	if initError != nil {
		return "", initError
	}

	username, found := uidUsernameMap[uid]
	if !found {
		return "", fmt.Errorf("UID %d not found", uid)
	}
	return username, nil
}
