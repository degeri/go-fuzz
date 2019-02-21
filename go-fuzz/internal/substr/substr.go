package substr

import (
	"bytes"
	"index/suffixarray"
	"math/rand"

	"github.com/dvyukov/go-fuzz/go-fuzz/internal/pcg"
)

type Corpus struct {
	r    *pcg.Source
	perm []int // all distinct indices into ss/bb/rk, in no particular order
	ss   []string
	bb   [][]byte // byte slice variants of ss
	rk   [][]int  // Rabin-Karp hashes of substrings of ss
}

func NewCorpus(r *rand.Rand, ss []string) *Corpus {
	c := new(Corpus)
	var seed [16]byte
	r.Read(seed[:])
	c.r = pcg.New(seed)
	c.ss = ss

	// Populate c.perm. It'll get shuffled around later.
	c.perm = make([]int, len(c.ss))
	for i := range c.ss {
		c.perm[i] = i
	}

	// Make a slice of byte slices containing the same contents as c.ss.
	// Use a single byte slice for cache happiness.
	c.bb = make([][]byte, len(c.ss))
	slen := 0
	for _, s := range c.ss {
		slen += len(s)
	}
	b := make([]byte, slen)
	n := 0
	for i, s := range c.ss {
		copy(b[n:], s)
		c.bb[i] = b[n : n+len(s) : n+len(s)]
		n += len(s)
	}

	// TODO: create c.rk
	return c
}

// Pick returns a random corpus element that is a substring of b.
// If no element of the corpus is a substring of s, it returns "".
func (c *Corpus) Pick(b []byte) []byte {
	const impl = 1

	// Implementation option 1: Pick a random element of the corpus, check whether it is a substring of s, return it if so.
	// This isn't a great choice, because it is very inefficient in the case in which no corpus element is a substring of s.
	if impl == 1 {
		// TODO: document this algorithm (obviously a Fischer-Yates variant),
		// and ensure that it doesn't have any off-by-one mistakes.
		p := c.perm
		for len(p) > 0 {
			// Select an element at random to try.
			idx := c.r.Uint32n(uint32(len(p)))
			x := p[idx]
			needle := c.bb[x]
			if bytes.Contains(b, needle) {
				return needle
			}
			// No luck. Move that element out of the way and try again.
			p[0], p[idx] = p[idx], p[0]
			// TODO: do this with base offset rather than indices to avoid re-slicing costs.
			p = p[1:]
		}
		// Didn't find anything.
		return nil
	}

	// Implementation option 2: Same as option 1, but using index/suffixarray.
	if impl == 2 {
		suff := suffixarray.New(b)
		p := c.perm
		for len(p) > 0 {
			// Select an element at random to try.
			idx := c.r.Uint32n(uint32(len(p)))
			x := p[idx]
			needle := c.bb[x]
			if len(suff.Lookup(needle, 1)) > 0 {
				return needle
			}
			// No luck. Move that element out of the way and try again.
			p[0], p[idx] = p[idx], p[0]
			// TODO: do this with base offset rather than indices to avoid re-slicing costs.
			p = p[1:]
		}
		// Didn't find anything.
		return nil
	}

	// Implementation option 3: Use a rolling hash (Rabin-Karp) to generate a signature for each corpus element.
	// Apply the rolling hash to s and use it to populate a Bloom Filter.
	// For each corpus element, use the Bloom Filter to try to rule it out.
	// Apply implementation option 1 or 2 from there.

	panic("no Pick implementation selected")
}

/*

// primeRK is the prime base used in Rabin-Karp algorithm.
const primeRK = 16777619

// hashStr returns the hash and the appropriate multiplicative
// factor for use in Rabin-Karp algorithm.
func hashStr(sep []byte) (uint32, uint32) {
	hash := uint32(0)
	for i := 0; i < len(sep); i++ {
		hash = hash*primeRK + uint32(sep[i])
	}
	var pow, sq uint32 = 1, primeRK
	for i := len(sep); i > 0; i >>= 1 {
		if i&1 != 0 {
			pow *= sq
		}
		sq *= sq
	}
	return hash, pow
}

func indexRabinKarp(s, sep []byte) int {
	// Rabin-Karp search
	hashsep, pow := hashStr(sep)
	n := len(sep)
	var h uint32
	for i := 0; i < n; i++ {
		h = h*primeRK + uint32(s[i])
	}
	if h == hashsep && Equal(s[:n], sep) {
		return 0
	}
	for i := n; i < len(s); {
		h *= primeRK
		h += uint32(s[i])
		h -= pow * uint32(s[i-n])
		i++
		if h == hashsep && Equal(s[i-n:i], sep) {
			return i - n
		}
	}
	return -1
}


*/
