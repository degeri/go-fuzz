#include "textflag.h"

// compareCoverBody1 compares every corresponding byte of base and cur, and
// reports whether cur has any entries bigger than base.
// func compareCoverBody1(base, cur *byte) bool
TEXT ·compareCoverBody1(SB), NOSPLIT, $0-17
	MOVQ	base+0(FP), SI
	MOVQ	cur+8(FP), DI
	XORQ	CX, CX	// loop counter
	XORQ	R10, R10	// ret

	// Fill X0 with 128.
	MOVL	$128, AX
	MOVD	AX, X0
	PUNPCKLBW X0, X0
	PUNPCKLBW X0, X0
	PSHUFL $0, X0, X0

	// TODO: nops for loop target alignment?
loop:
	MOVOU	(SI)(CX*1), X1
	MOVOU	(DI)(CX*1), X2
	// Add -128 to each byte.
	// This lets us use signed comparison below to implement unsigned comparison.
	PSUBB	X0, X1
	PSUBB	X0, X2
	// Compare each byte
	PCMPGTB	X1, X2 // X2 > X1
	// Extract top bit of each elem.
	PMOVMSKB X2, AX
	// If any bits were set, then some elem of X2 (cur) was bigger than some elem of X1 (base).
	TESTQ	AX, AX
	JNZ	yes
	LEAQ	16(CX), CX	// CX += 16
	BTL	$16, CX	// have we reached 65536 (CoverSize)?
	JCS	ret
	JMP	loop
yes:
	MOVQ	$1, R10
ret:
	MOVB	R10, ret+16(FP)
	RET

