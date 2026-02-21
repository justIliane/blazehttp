// Package debug provides conditional logging for BlazeHTTP.
// Logging is enabled by building with the "blazedebug" build tag.
package debug

// Printf logs a formatted message when debug mode is enabled.
// In production builds (without the blazedebug tag), this is a no-op
// that gets inlined and eliminated by the compiler.
func Printf(format string, args ...any) {
	debugPrintf(format, args...)
}
