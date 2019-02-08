// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
	"github.com/dvyukov/go-fuzz/go-fuzz/internal/substr"
)

type Mutator struct {
	r  *rand.Rand
	ro *ROData
	sc *substr.Corpus
}

func newMutator(metadata MetaData) *Mutator {
	m := new(Mutator)
	m.r = rand.New(rand.NewSource(time.Now().UnixNano())) // TODO: use crypto/rand.Reader instead? These get spawned really close to each other.
	corpus := make([]string, 0, len(metadata.Literals.Strings)+len(metadata.Literals.Ints))
	corpus = append(corpus, metadata.Literals.Strings...)
	corpus = append(corpus, metadata.Literals.Ints...)
	m.sc = substr.NewCorpus(m.r, corpus) // TODO: ints too? variants on strings like NUL term, length prefix?
	return m
}

func (m *Mutator) rand(n int) int {
	return m.r.Intn(n)
}

func (m *Mutator) randbool() bool {
	return m.r.Int63()&1 == 0
}

func (m *Mutator) randByteOrder() binary.ByteOrder {
	if m.randbool() {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// randSlice returns a random slice of b, of length n.
// If b is too short, randSlice returns nil.
func (m *Mutator) randSlice(b []byte, n int) []byte {
	// TODO: bias towards literal boundaries? NULs? etc.
	if len(b) < n {
		return nil
	}
	off := m.rand(len(b) - n + 1)
	return b[off : off+n]
}

func (m *Mutator) generate(ro *ROData) ([]byte, int) {
	corpus := ro.corpus
	scoreSum := corpus[len(corpus)-1].runningScoreSum
	weightedIdx := m.rand(scoreSum)
	idx := sort.Search(len(corpus), func(i int) bool {
		return corpus[i].runningScoreSum > weightedIdx
	})
	input := &corpus[idx]
	return m.mutate(input.data, ro), input.depth + 1
}

// TODO: restructure mutate
// Outline:
// Each mutation routine should be a separate function that takes params as needed.
// Any given mutation routine should be fully deterministic.
// This allows testability.
// This will also allow us to measure which mutations are (in)effective,
// and ultimately to skew our mutation efforts towards mutations that are effective
// for this particular corpus and Fuzz function.
// Some params really are random, like where to increment an int.
// That's fine; those can be populated after the top level dispatch.
// (It might even be interesting to learn, though, things like
// whether it is more beneficial to be near the beginning or the middle or the end,
// or whether there are fixed-length entries, or what.)
// TODO: when we restructure the for loop, make it so that we automatically do iter-- if bytes.Equal.

func (m *Mutator) mutate(data []byte, ro *ROData) []byte {
	corpus := ro.corpus
	res := make([]byte, len(data))
	copy(res, data)
	nm := 1
	for m.rand(2) == 0 {
		nm++
	}
	for iter := 0; iter < nm || bytes.Equal(res, data); iter++ {
		switch m.rand(21) {
		case 0:
			// Remove a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			pos0 := m.rand(len(res))
			pos1 := pos0 + m.chooseLen(len(res)-pos0)
			copy(res[pos0:], res[pos1:])
			res = res[:len(res)-(pos1-pos0)]
		case 1:
			// Insert a range of random bytes.
			pos := m.rand(len(res) + 1)
			n := m.chooseLen(10)
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos+n:], res[pos:])
			for i := 0; i < n; i++ {
				res[pos+i] = byte(m.rand(256))
			}
		case 2:
			// Duplicate a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			n := m.chooseLen(len(res) - src)
			tmp := make([]byte, n)
			copy(tmp, res[src:])
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[dst+n:], res[dst:])
			for i := 0; i < n; i++ {
				res[dst+i] = tmp[i]
			}
		case 3:
			// Copy a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			n := m.chooseLen(len(res) - src)
			if dst > len(res) || src+n > len(res) {
				println(len(res), dst, src, n)
			}
			copy(res[dst:], res[src:src+n])
		case 4:
			// Bit flip(s). Spooky!
			if len(res) == 0 {
				iter--
				continue
			}
			nflips := 1
			for m.randbool() {
				nflips++
			}
			for i := 0; i < nflips; i++ {
				pos := m.rand(len(res))
				res[pos] ^= 1 << uint(m.rand(8))
			}
		case 5:
			// Set a byte to a random value.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			res[pos] ^= byte(m.rand(255)) + 1
		case 6:
			// Swap 2 bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			res[src], res[dst] = res[dst], res[src]
		case 7:
			// Add/subtract from a byte.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			v := byte(m.rand(35) + 1)
			if m.randbool() {
				res[pos] += v
			} else {
				res[pos] -= v
			}
		case 8:
			// Add/subtract from a uint16.
			buf := m.randSlice(res, 2)
			if buf == nil {
				iter--
				continue
			}
			v := uint16(m.rand(35) + 1)
			if m.randbool() {
				v = ^(v - 1) // v *= -1, but for uints
			}
			enc := m.randByteOrder()
			enc.PutUint16(buf, enc.Uint16(buf)+v)
		case 9:
			// Add/subtract from a uint32.
			buf := m.randSlice(res, 4)
			if buf == nil {
				iter--
				continue
			}
			v := uint32(m.rand(35) + 1)
			if m.randbool() {
				v = ^(v - 1) // v *= -1, but for uints
			}
			enc := m.randByteOrder()
			enc.PutUint32(buf, enc.Uint32(buf)+v)
		case 10:
			// Add/subtract from a uint64.
			buf := m.randSlice(res, 8)
			if buf == nil {
				iter--
				continue
			}
			v := uint64(m.rand(35) + 1)
			if m.randbool() {
				v = ^(v - 1) // v *= -1, but for uints
			}
			enc := m.randByteOrder()
			enc.PutUint64(buf, enc.Uint64(buf)+v)
		case 11:
			// Replace a byte with an interesting value.
			if len(res) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(res))
			res[pos] = byte(interesting8[m.rand(len(interesting8))])
		case 12:
			// Replace an uint16 with an interesting value.
			buf := m.randSlice(res, 2)
			if buf == nil {
				iter--
				continue
			}
			v := uint16(interesting16[m.rand(len(interesting16))])
			m.randByteOrder().PutUint16(buf, v)
		case 13:
			// Replace an uint32 with an interesting value.
			buf := m.randSlice(res, 4)
			if buf == nil {
				iter--
				continue
			}
			v := uint32(interesting32[m.rand(len(interesting32))])
			m.randByteOrder().PutUint32(buf, v)
		case 14:
			// Replace an ascii digit with another digit.
			var digits []int
			for i, v := range res {
				if v >= '0' && v <= '9' {
					digits = append(digits, i)
				}
			}
			if len(digits) == 0 {
				iter--
				continue
			}
			pos := m.rand(len(digits))
			was := res[digits[pos]]
			now := byte(m.rand(10)) + '0'
			for was == now {
				now = byte(m.rand(10)) + '0'
			}
			res[digits[pos]] = now
		case 15:
			// Replace a multi-byte ASCII number with another number.
			type arange struct {
				start int
				end   int
			}
			var numbers []arange
			start := -1
			for i, v := range res {
				if (v >= '0' && v <= '9') || (start == -1 && v == '-') {
					if start == -1 {
						start = i
					} else if i == len(res)-1 {
						// At final byte.
						if i-start > 0 {
							numbers = append(numbers, arange{start, i + 1})
						}
					}
				} else {
					if start != -1 && i-start > 1 {
						numbers = append(numbers, arange{start, i})
						start = -1
					}
				}
			}
			if len(numbers) == 0 {
				iter--
				continue
			}
			r := numbers[m.rand(len(numbers))]
			var v int64
			switch m.rand(3) {
			case 0:
				v = int64(m.rand(1000))
			case 1:
				v = int64(m.rand(1 << 30))
			case 2:
				v = int64(m.rand(1<<30)) * int64(m.rand(1<<30))
			}
			if m.randbool() {
				v *= -1
			}
			str := strconv.FormatInt(v, 10)
			tmp := make([]byte, len(res)-(r.end-r.start)+len(str))
			copy(tmp, res[:r.start])
			copy(tmp[r.start:], str)
			copy(tmp[r.start+len(str):], res[r.end:])
			res = tmp
		case 16:
			// Splice another input.
			if len(res) < 4 || len(corpus) < 2 {
				iter--
				continue
			}
			other := corpus[m.rand(len(corpus))].data
			if len(other) < 4 || &res[0] == &other[0] {
				iter--
				continue
			}
			// Find common prefix and suffix.
			idx0 := 0
			for idx0 < len(res) && idx0 < len(other) && res[idx0] == other[idx0] {
				idx0++
			}
			idx1 := 0
			for idx1 < len(res) && idx1 < len(other) && res[len(res)-idx1-1] == other[len(other)-idx1-1] {
				idx1++
			}
			// If diffing parts are too small, there is no sense in splicing, rely on byte flipping.
			diff := min(len(res)-idx0-idx1, len(other)-idx0-idx1)
			if diff < 4 {
				iter--
				continue
			}
			copy(res[idx0:idx0+m.rand(diff-2)+1], other[idx0:])
			// TODO: use our splice routine to do more generic splicing, instead of just a half-and-half.
		case 17:
			// Insert a part of another input.
			if len(res) < 4 || len(corpus) < 2 {
				iter--
				continue
			}
			other := corpus[m.rand(len(corpus))].data
			if len(other) < 4 || &res[0] == &other[0] {
				iter--
				continue
			}
			pos0 := m.rand(len(res) + 1)
			pos1 := m.rand(len(other) - 2)
			n := m.chooseLen(len(other)-pos1-2) + 2
			for i := 0; i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos0+n:], res[pos0:])
			for i := 0; i < n; i++ {
				res[pos0+i] = other[pos1+i]
			}
		case 18:
			// Insert a literal.
			lit := m.pickLiteral(ro)
			if lit == nil {
				iter--
				continue
			}
			pos := m.rand(len(res) + 1)
			if pos == len(res)+1 {
				// TODO: make splice handle this case?
				res = append(res, lit...)
			} else {
				res = splice(res, pos, 0, lit)
			}
		case 19:
			// Replace random bytes with literal.
			lit := m.pickLiteral(ro)
			if lit == nil || len(lit) >= len(res) {
				iter--
				continue
			}
			buf := m.randSlice(res, len(lit))
			copy(buf, lit)
		case 20:
			r := string(res)
			lit := m.sc.Pick(r) // TODO: change pick signature, rationalize with the rest of corpus construction
			if lit == "" {
				iter--
				continue
			}
			// swap only one incidence
			// TODO: swap all, swap a random subset
			// TODO: write and use a generic splice function
			// TODO: pick only a like kind literal (string for string, int for int, etc.)
			replace := m.pickLiteral(ro)
			// loop until the replacement is different than the original
			for string(replace) == lit {
				replace = m.pickLiteral(ro)
			}

			// TODO: restructure
			// maybe: count number of instances
			// if 1 replace it, and done.
			// if not one, do as below?
			// maybe not emphasize first/last so much??

			switch m.rand(5) {
			case 0:
				// replace the first instance
				i := strings.Index(r, lit)
				if i < 0 {
					panic(fmt.Errorf("substr.Pick failed on %q %q", res, lit))
				}
				res = splice(res, i, len(lit), replace)
			case 1:
				// replace the last instance
				i := strings.LastIndex(r, lit)
				if i < 0 {
					panic(fmt.Errorf("substr.Pick failed on %q %q", res, lit))
				}
				res = splice(res, i, len(lit), replace)
			case 2:
				// replace all instances
				res = bytes.Replace(res, []byte(lit), replace, -1)
			case 3:
				// replace a random instance:
				// pick a random offset, find the first instance before/after that offset, replace it.
				pos := m.rand(len(res))
				i := strings.Index(r[pos:], lit)
				if i < 0 {
					i = strings.LastIndex(r[:pos], lit)
					if i < 0 {
						// we must be in the middle of the only instance of lit!
						// do a replace all, since that is simple to implement.
						// TODO: restructure all of this for unity?
						res = bytes.Replace(res, []byte(lit), replace, -1)
						break
					}
				} else {
					i += pos
				}
				res = splice(res, i, len(lit), replace)
			case 4:
				// replace random instances with probably 1/2 for each
				// TODO: pick different lits for each replacement?
				var tmp []byte
				fields := strings.Split(r, lit)
				for i, field := range fields {
					if i == len(fields)-1 {
						break
					}
					tmp = append(tmp, field...)
					if m.randbool() {
						tmp = append(tmp, lit...)
					} else {
						tmp = append(tmp, replace...)
					}
				}
				res = tmp
			}
		case 21:
			panic("disabled -- leads to overlong inputs")
			// Append another input wholesale.
			// TODO: this probably leads to overlong inputs. remove?
			// Insert a part of another input.
			if len(res) < 1 || len(corpus) < 2 {
				iter--
				continue
			}
			other := corpus[m.rand(len(corpus))].data
			// TODO: does this do the right thing when res has already been replaced?
			// TODO: maybe shouldn't bother, doesn't hurt to append self to self.
			if len(other) < 1 || &res[0] == &other[0] {
				iter--
				continue
			}
			res = append(res, other...)
		}
		// Ideas for more mutations:
		// Instead of swapping just two bytes, swap two disjoint byte ranges of the same random length.
		// search and replace a literal with another literal! either replace all or replace one or replace random subset.
		// Swap case of ascii letters?
		// lowercase run of ascii letters?
		// uppercase run of ascii letters?
	}
	if len(res) > MaxInputSize {
		res = m.randSlice(res, MaxInputSize)
	}
	return res
}

func (m *Mutator) pickLiteral(ro *ROData) []byte {
	// TODO: encode int literals in big-endian, base-128, ascii, etc.
	// TODO: other kinds of literals
	// TODO: encode strings with length prefix and with trailing NUL
	if len(ro.intLits) == 0 && len(ro.strLits) == 0 {
		return nil
	}
	var lit []byte
	if len(ro.strLits) != 0 && m.rand(2) == 0 {
		lit = []byte(ro.strLits[m.rand(len(ro.strLits))])
	} else {
		lit = ro.intLits[m.rand(len(ro.intLits))]
		if m.rand(3) == 0 {
			lit = reverse(lit)
		}
	}
	return lit
}

// chooseLen chooses length of range mutation.
// It gives preference to shorter ranges.
// TODO: Zipf instead? Examine distribution.
func (m *Mutator) chooseLen(n int) int {
	switch x := m.rand(100); {
	case x < 90:
		return m.rand(min(8, n)) + 1
	case x < 99:
		return m.rand(min(32, n)) + 1
	default:
		return m.rand(n) + 1
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// splice replaces s[start:start+n] with r.
// It might modify s in the process.
// TODO: write some tests of this!
func splice(s []byte, start, n int, r []byte) []byte {
	if len(r) == n {
		// Easy case: overwrite the relevant bytes.
		copy(s[start:], r)
		return s
	}
	newlen := len(s) - n + len(r)
	if newlen <= cap(s) {
		// The new output will fit in s; re-use it.
		tail := s[start+n:] // calculate tail before re-slicing s
		s = s[:newlen]
		copy(s[start:], r)
		copy(s[start+len(r):], tail)
		return s
	}
	// The new output doesn't fit. Construct a new slice.
	t := make([]byte, newlen)
	copy(t, s[:start])
	copy(t[start:], r)
	copy(t[start+len(r):], s[start+n:])
	return t
}

var (
	interesting8  = []int8{-128, -1, 0, 1, 16, 32, 64, 100, 127}
	interesting16 = []int16{-32768, -129, 128, 255, 256, 512, 1000, 1024, 4096, 32767}
	interesting32 = []int32{-2147483648, -100663046, -32769, 32768, 65535, 65536, 100663045, 2147483647}
)

func init() {
	for _, v := range interesting8 {
		interesting16 = append(interesting16, int16(v))
	}
	for _, v := range interesting16 {
		interesting32 = append(interesting32, int32(v))
	}
}
