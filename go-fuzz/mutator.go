// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/flate"
	"compress/lzw"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/bits"
	"math/rand"
	"sort"
	"strconv"
	"strings"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
	"github.com/dvyukov/go-fuzz/go-fuzz/internal/pcg"
	"github.com/dvyukov/go-fuzz/go-fuzz/internal/substr"
)

type mutationSource struct {
	Choices       []Choice
	Iters         int
	InitialLen    int
	ExecType      byte
	Sonar         string
	InitialCorpus bool
}

type Choice struct {
	Which   uint32
	Sub     []int
	Useless bool
}

func (s *mutationSource) String() string {
	b := new(strings.Builder)
	if s.InitialCorpus {
		fmt.Fprint(b, "initial corpus- ")
	}
	if len(s.Choices) == 0 && s.Sonar == "" {
		fmt.Fprintf(b, "<%v>", s.ExecType)
		return b.String()
	}
	if s.Sonar != "" {
		fmt.Fprintf(b, "%s ", s.Sonar)
	}
	// fmt.Fprintf(b, "in=%d ", s.InitialLen)
	// fmt.Fprintf(b, "iters=%d: ", s.Iters)
	for _, c := range s.Choices {
		if c.Useless {
			// fmt.Fprintf(b, "(%d)", c.Which)
		} else {
			if len(c.Sub) > 0 {
				fmt.Fprintf(b, "%d %v, ", c.Which, c.Sub)
			} else {
				fmt.Fprintf(b, "%d, ", c.Which)
			}
		}
	}
	// fmt.Fprintf(b, " <%v>", s.ExecType[len(s.ExecType)-1])
	return b.String()
}

type Mutator struct {
	r            *pcg.Source
	ro           *ROData
	sc           *substr.Corpus
	sonarsamples map[string]struct{}
	buf          bytes.Buffer
	flateWriters []*flate.Writer
}

func (m *Mutator) addSonarSample(b []byte) {
	// TODO: differentiate between different kinds of sonar samples: strings, ints, etc.
	if len(b) < 2 {
		return
	}
	if _, ok := m.sonarsamples[string(b)]; ok {
		return
	}
	m.sonarsamples[string(b)] = struct{}{}
	fmt.Printf("ACCEPT %q -> %d\n", b, len(m.sonarsamples))
}

func newMutator(metadata MetaData, r *rand.Rand) *Mutator {
	m := new(Mutator)

	var seed [16]byte
	r.Read(seed[:])
	m.r = pcg.New(seed)

	corpus := make([]string, 0, len(metadata.Literals.Strings)+len(metadata.Literals.Ints))
	corpus = append(corpus, metadata.Literals.Strings...)
	corpus = append(corpus, metadata.Literals.Ints...)
	m.sc = substr.NewCorpus(r, corpus) // TODO: ints too? variants on strings like NUL term, length prefix?
	m.sonarsamples = make(map[string]struct{})
	for i := 0; i <= 9; i++ {
		var w *flate.Writer
		if i == 0 {
			w, _ = flate.NewWriter(nil, flate.HuffmanOnly)
		} else {
			w, _ = flate.NewWriter(nil, i)
		}
		m.flateWriters = append(m.flateWriters, w)
	}
	return m
}

func (m *Mutator) rand(n int) uint32 {
	return m.r.Uint32n(uint32(n))
}

func (m *Mutator) randbool() bool {
	return m.r.Uint64()&1 == 0
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
	return b[off : off+uint32(n)]
}

// randExp2 returns n > 0 with probability 1/2^n.
// TODO: better docs
func (m *Mutator) randExp2() int {
	return bits.LeadingZeros64(m.r.Uint64()) + 1
}

func (m *Mutator) generate(ro *ROData) ([]byte, *mutationSource, int) {
	corpus := ro.corpus
	scoreSum := corpus[len(corpus)-1].runningScoreSum
	weightedIdx := m.rand(int(scoreSum))
	idx := sort.Search(len(corpus), func(i int) bool {
		return corpus[i].runningScoreSum > weightedIdx
	})
	input := &corpus[idx]
	data, whence := m.mutate(input.data, ro)
	return data, whence, input.depth + 1
}

const nMutations = 23

const epsilon = 90 // 0 = always exploit (if possible); 100 = always explore

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

func (m *Mutator) mutate(data []byte, ro *ROData) ([]byte, *mutationSource) {
	corpus := ro.corpus
	res := make([]byte, len(data))
	copy(res, data)
	nm := m.randExp2()
	whence := new(mutationSource)
	whence.Iters = nm
	whence.InitialLen = len(data)
	previter := 0
	for iter := 0; iter < nm || bytes.Equal(res, data); iter++ {
		if (iter == previter || bytes.Equal(res, data)) && len(whence.Choices) > 0 {
			whence.Choices[len(whence.Choices)-1].Useless = true
		}
		previter = iter

		var which uint32
		if !ro.canExploit /* must explore */ || m.rand(100) < epsilon /* explore according to epsilon */ {
			// explore
			which = m.rand(nMutations)
		} else {
			// exploit
			// TODO: Exploit more aggressively.
			// In theory, we should always pick the one with the highest score here.
			// For now, though, pick proportional to the weights (Thompson Sampling) as hedge.
			// There's a whole literature on this stuff.
			// Should switch to something more principled,
			// which also takes into account moving scores over time.
			w := m.rand(int(ro.mutWeights[len(ro.mutWeights)-1])) // TODO: off by one here??

			idx := sort.Search(len(ro.mutWeights), func(i int) bool {
				return ro.mutWeights[i] > w
			})
			which = uint32(idx)
		}

		choice := Choice{Which: which}
		whence.Choices = append(whence.Choices, choice)
		c := &whence.Choices[len(whence.Choices)-1]
		switch which {
		case 0:
			// Remove a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			pos0 := m.rand(len(res))
			pos1 := pos0 + m.chooseLen(len(res)-int(pos0))
			copy(res[pos0:], res[pos1:])
			res = res[:uint32(len(res))-(pos1-pos0)]
		case 1:
			// Insert a range of random bytes.
			// TODO: use splice
			pos := m.rand(len(res) + 1)
			n := m.chooseLen(10)
			// c.Sub = append(c.Sub, n)
			for i := uint32(0); i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos+n:], res[pos:])
			for i := uint32(0); i < n; i++ {
				res[pos+i] = byte(m.rand(256))
			}
		case 2:
			// Duplicate a range of bytes.
			if len(res) <= 1 {
				iter--
				continue
			}
			// TODO: use splice
			src := m.rand(len(res))
			dst := m.rand(len(res))
			for dst == src {
				dst = m.rand(len(res))
			}
			n := m.chooseLen(len(res) - int(src))
			tmp := make([]byte, n)
			copy(tmp, res[src:])
			for i := uint32(0); i < n; i++ {
				res = append(res, 0)
			}
			copy(res[dst+n:], res[dst:])
			// TODO: use copy??
			for i := uint32(0); i < n; i++ {
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
			n := m.chooseLen(len(res) - int(src))
			copy(res[dst:], res[src:src+n])
		case 4:
			// Bit flip(s). Spooky!
			if len(res) == 0 {
				iter--
				continue
			}
			nflips := m.randExp2()
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
			copy(res[idx0:uint32(idx0)+m.rand(diff-2)+1], other[idx0:])
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
			n := m.chooseLen(len(other)-int(pos1)-2) + 2
			for i := uint32(0); i < n; i++ {
				res = append(res, 0)
			}
			copy(res[pos0+n:], res[pos0:])
			// TODO: use copy?
			for i := uint32(0); i < n; i++ {
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
			if int(pos) == len(res)+1 {
				// TODO: make splice handle this case?
				res = append(res, lit...)
			} else {
				res = splice(res, int(pos), 0, lit)
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
			lit := m.sc.Pick(res)
			if lit == nil {
				iter--
				continue
			}
			// swap only one incidence
			// TODO: swap all, swap a random subset
			// TODO: write and use a generic splice function
			// TODO: pick only a like kind literal (string for string, int for int, etc.)
			replace := m.pickLiteral(ro)
			// loop until the replacement is different than the original
			for bytes.Equal(replace, lit) {
				replace = m.pickLiteral(ro)
			}

			// TODO: restructure
			// maybe: count number of instances
			// if 1 replace it, and done.
			// if not one, do as below?
			// maybe not emphasize first/last so much??

			sub := m.rand(5)
			// c.Sub = append(c.Sub, sub)
			switch sub {
			case 0:
				// replace the first instance
				i := bytes.Index(res, lit)
				if i < 0 {
					panic(fmt.Errorf("substr.Pick failed on %q %q", res, lit))
				}
				res = splice(res, i, len(lit), replace)
			case 1:
				// replace the last instance
				i := bytes.LastIndex(res, lit)
				if i < 0 {
					panic(fmt.Errorf("substr.Pick failed on %q %q", res, lit))
				}
				res = splice(res, i, len(lit), replace)
			case 2:
				// replace all instances
				res = bytes.Replace(res, lit, replace, -1)
			case 3:
				// replace a random instance:
				// pick a random offset, find the first instance before/after that offset, replace it.
				pos := m.rand(len(res))
				i := bytes.Index(res[pos:], lit)
				if i < 0 {
					i = bytes.LastIndex(res[:pos], lit)
					if i < 0 {
						// we must be in the middle of the only instance of lit!
						// do a replace all, since that is simple to implement.
						// TODO: restructure all of this for unity?
						res = bytes.Replace(res, lit, replace, -1)
						break
					}
				} else {
					i += int(pos)
				}
				res = splice(res, i, len(lit), replace)
			case 4:
				// replace random instances with probably 1/2 for each
				// TODO: pick different lits for each replacement?
				var tmp []byte
				fields := bytes.Split(res, lit)
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
			if len(res) == 0 {
				iter--
				continue
			}
			buf := &m.buf
			buf.Reset()
			order := lzw.LSB
			// TODO: does the bit order matter, given how we are using this?
			if m.randbool() {
				order = lzw.MSB
			}
			w := lzw.NewWriter(buf, order, 8)
			if _, err := w.Write(res); err != nil {
				panic(err)
			}
			if err := w.Close(); err != nil {
				panic(err)
			}
			b := buf.Bytes()
			iters := 1 //m.randExp2()
			for i := 0; i < iters; i++ {
				// TODO: skew towards beginning?? -- unclear, but looks like no?
				// TODO: multiple bit flips (exponential)?
				pos := rand.Intn(len(b))
				c.Sub = append(c.Sub, int(float64(10*pos)/float64(len(b))))
				b[pos] ^= 1 << uint(rand.Intn(8))
			}
			r := lzw.NewReader(buf, order, 8)
			// intentionally ignore err from this read: we've corrupted the stream, so it is probably broken.
			// TODO: use ReadFull to read into res and then truncate;
			// if res is full, then append, reslice, and read the rest
			// same for flate below.
			// maybe also have another reusable tmp slice in the mutator?
			res, _ = ioutil.ReadAll(r)
			r.Close()
		case 22:
			buf := &m.buf
			buf.Reset()
			level := m.rand(len(m.flateWriters))
			w := m.flateWriters[level]
			// c.Sub = append(c.Sub, level)
			w.Reset(buf)
			if _, err := w.Write(res); err != nil {
				panic(err)
			}
			if err := w.Flush(); err != nil {
				panic(err)
			}
			b := buf.Bytes()
			// TODO: prefer to flip a bit near the beginning? -- not super clear, but looks like slightly yes
			// TODO: multiple bit flips (exponential)?
			iters := 1 //m.randExp2()
			for i := 0; i < iters; i++ {
				pos := rand.Intn(len(b))
				c.Sub = append(c.Sub, int(float64(10*pos)/float64(len(b))))
				b[pos] ^= 1 << uint(rand.Intn(8))
			}
			r := flate.NewReader(bytes.NewReader(b))
			// intentionally ignore err from this copy: we've corrupted the stream, so it is probably broken.
			// todo: optimize to allocate less, see above
			res, _ = ioutil.ReadAll(r)
			r.Close()
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
	return res, whence
}

func (m *Mutator) pickLiteral(ro *ROData) []byte {
	// TODO: encode int literals in big-endian, base-128, ascii, etc.
	// TODO: other kinds of literals
	// TODO: encode strings with length prefix and with trailing NUL
	if len(ro.intLits) == 0 && len(ro.strLits) == 0 && len(m.sonarsamples) == 0 {
		return nil
	}
	var lit []byte
	var order [2]int
	if m.randbool() {
		order = [2]int{0, 1}
	} else {
		order = [2]int{1, 0}
	}
	for _, choice := range &order {
		switch choice {
		case 0:
			if len(ro.strLits) == 0 {
				continue
			}
			lit = []byte(ro.strLits[m.rand(len(ro.strLits))])
		case 1:
			if len(ro.intLits) == 0 {
				continue
			}
			lit = ro.intLits[m.rand(len(ro.intLits))]
			if m.rand(3) == 0 {
				lit = reverse(lit)
			}
		case 2:
			if len(m.sonarsamples) == 0 {
				continue
			}
			for k := range m.sonarsamples {
				lit = []byte(k)
				break
			}
		}
	}
	return lit
}

// chooseLen chooses length of range mutation.
// It gives preference to shorter ranges.
// TODO: Zipf instead? Examine distribution.
func (m *Mutator) chooseLen(n int) uint32 {
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
