//go:build blazedebug

package debug

import "log"

func debugPrintf(format string, args ...any) {
	log.Printf("[BLAZE] "+format, args...)
}
