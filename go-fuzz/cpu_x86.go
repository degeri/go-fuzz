// +build 386 amd64 amd64p32

package main

// Adapted from GOROOT/src/internal/cpu/cpu_x86.go.

var hasAVX2 bool

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)
func xgetbv() (eax, edx uint32)

const (
	// ecx bits
	cpuid_OSXSAVE = 1 << 27

	// ebx bits
	cpuid_AVX2 = 1 << 5
)

func init() {
	_, _, ecx1, _ := cpuid(1, 0)
	hasOSXSAVE := isSet(ecx1, cpuid_OSXSAVE)

	osSupportsAVX := false
	// For XGETBV, OSXSAVE bit is required and sufficient.
	if hasOSXSAVE {
		eax, _ := xgetbv()
		// Check if XMM and YMM registers have OS support.
		osSupportsAVX = isSet(eax, 1<<1) && isSet(eax, 1<<2)
	}

	_, ebx7, _, _ := cpuid(7, 0)
	hasAVX2 = isSet(ebx7, cpuid_AVX2) && osSupportsAVX
}

func isSet(hwc uint32, value uint32) bool {
	return hwc&value != 0
}

// For future imaginary AVX512BW support:
// const cpuid_AVX512BW = 1 << 30 // source: https://en.wikipedia.org/wiki/CPUID
