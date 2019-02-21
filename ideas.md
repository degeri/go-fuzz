NEXT NEXT NEXT NEXT

adapt to larger coverage by switching to larger coverage array
manually? automatically?
idea: weigh literals less the farther they are from the fuzz fn.
  maybe this means package dependency depth.
  maybe function call depth?
  maybe even do a reachability analysis and seriously discount literals that aren't reachable from the fuzz function.
  and maybe even eliminate unreachable literals entirely if the analysis is precise (reflect/unsafe/cgo are not present).


todo: log differently when warming up (ingesting corpus) vs exploring
allow TTL to kick in only after warm-up

gather data as yoou go about what mutations led to new coverage, prefer those

ideas:

Fuzz(t T) // T is a struct, use gob encoding, for crashers auto generate json and regress as well as output
Store lit type with lits, then generate variants on demand (string: bytes, length-prefixed, nul terminated; ints: big/little/varint, various widths, ascii)
When using sonar or lits, track which kinds generate new coverage, learn about whether ints are big/little, etc. could maybe also infer from corpus given lits
sonar: replace all matches, replace each single match, replace a random subset
flags: TTL, output type (txt vs csv), execs before restart

increase size of coverage array as coverage grows. or maybe add augmentary coverage arrays? maybe use a count min sketch?

ignore package log during literal collection *unless* fuzzing package log; same for fmt, errors
recognize stringer-generated code, ignore string blocks
prefer shorter string literals during mutation(?)
consider reworking coverage block entries in metadata to be shorter (organize by file first, then...) or have ID be implicit by making it an array? make list of files that we can index into?

rarely, try systematically altering a corpus entry, probably by zeroing one byte at a time.
use this to discover "data" vs "structure" areas. then focus mutations depending on what kind of area it is.

---

metric: average corpus length?

idea: analysis coverage information to discover bottlenecks: places where coverage stops entirely, indicating a place has gotten stuck fuzzing.
inspect to find new mutations, sonar, etc.

idea: track whence each corpus entry (manual, sonar, verse, mutation), see whether the optimal source changes over time

ignore stringer literals (or recognize them and bust them apart?)

---

make initial startup faster by doing less work on existing corpus entries?

---

anecdotally, new corpus entries get found faster shortly after initial triage is complete.
then it slows down. is this accurate? if so, why??

---

do coverage analysis at build time: build a graph (grid?) of distances from every block to another.
use this information to better estimate "depth" -- not the number of mutations, but how far
into the code a corpus entry actually reaches. (maybe use the new analysis toy?)


---

when minimizing, each time an alteration succeeds, go to beginning again

---

bring smash-mutate-uniq into kitchensink?
strengthen it by handling other places where mutated inputs are in use?
use a stable bloom filter to implement more cheaply?

---


when coordinator and worker and hub etc are all in process, instead of using RPC, just make function calls.
heopfully will reduce time spent in the scheduler, which is not inconsiderable.


---

look at results
reply to dmitry, david
upstream type-precision
improve literals (more precise)
investigate what takes so much time with sonar; understand it better
figure out which sonar things work best/worst
figure out which fuzz things work best/worst
manually look at generated code
go/packages support
reduce byte slice allocations somehow, throughout
finish thinking about go-bindata

rewrite go-fuzz-build to use go/packages
more literals improvements, including how they get stored...
embed everything into a fuzz executable

todo from processSonarData:

		// TODO: extract literal corpus from sonar instead of from source.
		// This should give smaller, better corpus which does not contain literals from dead code.

maybe have a separate sonar literal set?
also, detect at least trivially dead code?

why does it generate lots of new coverage each time it restarts but seem to get "stuck" after a while of running??
theory: depth impact on scores?
new theory: minimization helps a lot--occasionally re-minimize our corpus?!
or just turn down sonar? or do a batch of sonar and then a batch of versing and then a batch of fuzzing?

WHAT IS THIS??? Can we replicate it somehow???
Or it is just the warm-up? Probably just warm-up, actually,
if there's no exec type...
 85.01%   686 NEW COVERAGE VIA initial corpus- 

---

avoid network connection to own process, just call func instead, might reduce scheduler churn
improve literal collection again (no stringer files, don't throw in a million ints in little/big/etc form, do that lazily)

---

apply epsilon-greedy decision making to sonar, versifier, MUST account for cost!

