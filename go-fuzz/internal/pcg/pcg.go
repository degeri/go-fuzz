// Package pcg provides a PCG-based PRNG and minimal associated functions.
package pcg

import (
	"encoding/binary"
	"math/bits"
)

// The PCG generator below is modified from golang.org/x/exp/rand by Rob Pike.
// See https://github.com/golang/go/issues/21835.

// The Int31n method is modified from the Go std math/rand's int31n (unexported).

const (
	maxUint64 = (1 << 64) - 1

	multiplier = 47026247687942121848144207491837523525 // PCG_DEFAULT_MULTIPLIER_128
	mulHigh    = multiplier >> 64
	mulLow     = multiplier & maxUint64

	increment = 117397592171526113268558934119004209487 // PCG_DEFAULT_INCREMENT_128
	incHigh   = increment >> 64
	incLow    = increment & maxUint64
)

// Source is an implementation of a 64-bit permuted congruential
// generator as defined in
//
// 	PCG: A Family of Simple Fast Space-Efficient Statistically Good
// 	Algorithms for Random Number Generation
// 	Melissa E. O’Neill, Harvey Mudd College
// 	http://www.pcg-random.org/pdf/toms-oneill-pcg-family-v1.02.pdf
//
// The generator here is the congruential generator PCG XSL RR 128/64 (LCG)
// as found in the software available at http://www.pcg-random.org/.
// It has period 2^128 with 128 bits of state, producing 64-bit values.
// Is state is represented by two uint64 words.
type Source struct {
	low  uint64
	high uint64
}

// Seed uses the provided seed value to initialize the generator to a deterministic state.
func New(seed [16]byte) *Source {
	pcg := new(Source)
	pcg.low = binary.LittleEndian.Uint64(seed[0:8])
	pcg.high = binary.LittleEndian.Uint64(seed[8:16])
	return pcg
}

// Uint64 returns a pseudo-random 64-bit unsigned integer as a uint64.
func (pcg *Source) Uint64() uint64 {
	// multiply
	hi, lo := bits.Mul64(pcg.low, mulLow)
	hi += pcg.high * mulLow
	hi += pcg.low * mulHigh
	pcg.low = lo
	pcg.high = hi

	// add
	var carry uint64
	pcg.low, carry = bits.Add64(pcg.low, incLow, 0)
	pcg.high, _ = bits.Add64(pcg.high, incHigh, carry)

	// XOR high and low 64 bits together and rotate right by high 6 bits of state.
	return bits.RotateLeft64(pcg.high^pcg.low, -int(pcg.high>>58))
}

// Int31n returns a pseudo-random number in [0, n).
//
// For implementation details, see:
// https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction
// https://lemire.me/blog/2016/06/30/fast-random-shuffling
func (pcg *Source) Uint32n(n uint32) uint32 {
	v := uint32(pcg.Uint64())
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < n {
		thresh := uint32(-int32(n)) % n
		for low < thresh {
			v = uint32(pcg.Uint64())
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return uint32(prod >> 32)
}
