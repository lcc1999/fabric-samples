package bfv

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// GaloisGen is an integer of order N=2^d modulo M=2N and that spans Z_M with the integer -1.
// The j-th ring automorphism takes the root zeta to zeta^(5j).
const GaloisGen uint64 = ring.GaloisGen

// Encoder is an interface for plaintext encoding and decoding operations. It provides methods to embed []uint64 and []int64 types into
// the various plaintext types and the inverse operations. It also provides methods to convert between the different plaintext types.
// The different plaintext types represent different embeddings of the message in the polynomial space. This relation is illustrated in
// the figure below:
//
//	                  ┌-> Encoder.Encode(.) -----------------------------------------------------┐
//	[]uint64/[]int64 -┼-> Encoder.EncodeRingT(.) ---> PlaintextRingT -┬-> Encoder.ScaleUp(.) ----┴-> rlwe.Plaintext
//	                  |                                               └-> Encoder.RingTToMul(.) -┬-> PlaintextMul
//	                  └-> Encoder.EncodeMul(.) --------------------------------------------------┘
//
// The different plaintext types have different efficiency-related characteristics that we summarize in the Table below. For more information
// about the different plaintext types, see plaintext.go.
//
// Relative efficiency of operations
//
//	 -------------------------------------------------------------------------
//	|                      |  PlaintextRingT  |  Plaintext  | PlaintextMul    |
//	 -------------------------------------------------------------------------
//	| Encoding/Decoding    |    Faster        |    Slower   |    Slower       |
//	| Memory size          |    Smaller       |    Larger   |    Larger       |
//	| Ct-Pt Add / Sub      |    Slower        |    Faster   |    N/A          |
//	| Ct-Pt Mul            |    Faster        |    Slower   |    Much Faster  |
//	 -------------------------------------------------------------------------
type Encoder interface {
	Encode(coeffs interface{}, pt *rlwe.Plaintext)
	EncodeNew(coeffs interface{}, level int) (pt *rlwe.Plaintext)
	EncodeRingT(coeffs interface{}, pt *PlaintextRingT)
	EncodeRingTNew(coeffs interface{}) (pt *PlaintextRingT)
	EncodeMul(coeffs interface{}, pt *PlaintextMul)
	EncodeMulNew(coeffs interface{}, level int) (pt *PlaintextMul)

	SwitchToRingT(pt interface{}, ptRt *PlaintextRingT)
	ScaleUp(ptRt *PlaintextRingT, pt *rlwe.Plaintext)
	ScaleDown(pt *rlwe.Plaintext, ptRt *PlaintextRingT)
	RingTToMul(ptRt *PlaintextRingT, ptmul *PlaintextMul)
	MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT)

	Decode(pt interface{}, coeffs interface{})
	DecodeUintNew(pt interface{}) (coeffs []uint64)
	DecodeIntNew(pt interface{}) (coeffs []int64)

	ShallowCopy() Encoder
}

// encoder is a structure that stores the parameters to encode values on a plaintext in a SIMD (Single-Instruction Multiple-Data) fashion.
type encoder struct {
	params Parameters

	indexMatrix []uint64
	scaler      Scaler

	tmpPoly *ring.Poly
	tmpPtRt *PlaintextRingT
}

// NewEncoder creates a new encoder from the provided parameters.
func NewEncoder(params Parameters) Encoder {

	var N, logN, pow, pos uint64 = uint64(params.N()), uint64(params.LogN()), 1, 0

	mask := 2*N - 1

	indexMatrix := make([]uint64, N)

	for i, j := 0, int(N>>1); i < int(N>>1); i, j = i+1, j+1 {

		pos = utils.BitReverse64(pow>>1, logN)

		indexMatrix[i] = pos
		indexMatrix[j] = N - pos - 1

		pow *= GaloisGen
		pow &= mask
	}

	return &encoder{
		params:      params,
		indexMatrix: indexMatrix,
		scaler:      NewRNSScaler(params.RingQ(), params.T()),
		tmpPoly:     params.RingQ().NewPoly(),
		tmpPtRt:     NewPlaintextRingT(params),
	}
}

// EncodeNew encodes a slice of integers of type []uint64 or []int64 of size at most N on a newly allocated plaintext.
func (ecd *encoder) EncodeNew(values interface{}, level int) (pt *rlwe.Plaintext) {
	pt = NewPlaintext(ecd.params, level)
	ecd.Encode(values, pt)
	return
}

// Encode encodes a slice of integers of type []uint64 or []int64 of size at most N into a pre-allocated plaintext.
func (ecd *encoder) Encode(values interface{}, pt *rlwe.Plaintext) {
	ptRt := &PlaintextRingT{pt}

	// Encodes the values in RingT
	ecd.EncodeRingT(values, ptRt)

	// Scales by Q/t
	ecd.ScaleUp(ptRt, pt)
}

// EncodeRingTNew encodes a slice of integers of type []uint64 or []int64 of size at most N into a newly allocated PlaintextRingT.
func (ecd *encoder) EncodeRingTNew(values interface{}) (pt *PlaintextRingT) {
	pt = NewPlaintextRingT(ecd.params)
	ecd.EncodeRingT(values, pt)
	return
}

// EncodeRingT encodes a slice of integers of type []uint64 or []int64 of size at most N into a pre-allocated PlaintextRingT.
// The input values are reduced modulo T before encoding.
func (ecd *encoder) EncodeRingT(values interface{}, ptOut *PlaintextRingT) {

	if len(ptOut.Value.Coeffs[0]) != len(ecd.indexMatrix) {
		panic("cannot EncodeRingT: invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	pt := ptOut.Value.Coeffs[0]

	ringT := ecd.params.RingT()

	var valLen int
	switch values := values.(type) {
	case []uint64:
		for i, c := range values {
			pt[ecd.indexMatrix[i]] = c
		}
		ringT.Reduce(ptOut.Value, ptOut.Value)
		valLen = len(values)
	case []int64:

		T := ringT.SubRings[0].Modulus
		BRedConstantT := ringT.SubRings[0].BRedConstant

		var sign, abs uint64
		for i, c := range values {
			sign = uint64(c) >> 63
			abs = ring.BRedAdd(uint64(c*((int64(sign)^1)-int64(sign))), T, BRedConstantT)
			pt[ecd.indexMatrix[i]] = sign*(T-abs) | (sign^1)*abs
		}
		valLen = len(values)
	default:
		panic("cannot EncodeRingT: coeffs must be either []uint64 or []int64")
	}

	for i := valLen; i < len(ecd.indexMatrix); i++ {
		pt[ecd.indexMatrix[i]] = 0
	}

	ringT.INTT(ptOut.Value, ptOut.Value)
}

// EncodeMulNew encodes a slice of integers of type []uint64 or []int64 of size at most N into a newly allocated PlaintextMul (optimized for ciphertext-plaintext multiplication).
func (ecd *encoder) EncodeMulNew(coeffs interface{}, level int) (pt *PlaintextMul) {
	pt = NewPlaintextMul(ecd.params, level)
	ecd.EncodeMul(coeffs, pt)
	return
}

// EncodeMul encodes a slice of integers of type []uint64 or []int64 of size at most N into a pre-allocated PlaintextMul (optimized for ciphertext-plaintext multiplication).
func (ecd *encoder) EncodeMul(coeffs interface{}, pt *PlaintextMul) {

	ptRt := &PlaintextRingT{pt.Plaintext}

	// Encodes the values in RingT
	ecd.EncodeRingT(coeffs, ptRt)

	// Puts in NTT+Montgomery domains of ringQ
	ecd.RingTToMul(ptRt, pt)
}

// ScaleUp transforms a PlaintextRingT (R_t) into a Plaintext (R_q) by scaling up the coefficient by Q/t.
func (ecd *encoder) ScaleUp(ptRt *PlaintextRingT, pt *rlwe.Plaintext) {
	ecd.scaler.ScaleUpByQOverTLvl(pt.Level(), ptRt.Value, pt.Value)
}

// ScaleDown transforms a Plaintext (R_q) into a PlaintextRingT (R_t) by scaling down the coefficient by t/Q and rounding.
func (ecd *encoder) ScaleDown(pt *rlwe.Plaintext, ptRt *PlaintextRingT) {
	ecd.scaler.DivByQOverTRoundedLvl(pt.Level(), pt.Value, ptRt.Value)
}

// RingTToMul transforms a PlaintextRingT into a PlaintextMul by performing the NTT transform
// of R_q and putting the coefficients in Montgomery form.
func (ecd *encoder) RingTToMul(ptRt *PlaintextRingT, ptMul *PlaintextMul) {

	level := ptMul.Level()

	if ptRt.Value != ptMul.Value {
		copy(ptMul.Value.Coeffs[0], ptRt.Value.Coeffs[0])
	}
	for i := 1; i < level+1; i++ {
		copy(ptMul.Value.Coeffs[i], ptRt.Value.Coeffs[0])
	}

	ringQ := ecd.params.RingQ().AtLevel(level)

	ringQ.NTTLazy(ptMul.Value, ptMul.Value)
	ringQ.MForm(ptMul.Value, ptMul.Value)
}

// MulToRingT transforms a PlaintextMul into PlaintextRingT by performing the inverse NTT transform of R_q and
// putting the coefficients out of the Montgomery form.
func (ecd *encoder) MulToRingT(pt *PlaintextMul, ptRt *PlaintextRingT) {
	ringQ := ecd.params.RingQ().AtLevel(0)
	ringQ.INTTLazy(pt.Value, ptRt.Value)
	ringQ.IMForm(ptRt.Value, ptRt.Value)
}

// SwitchToRingT decodes any plaintext type into a PlaintextRingT. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) SwitchToRingT(p interface{}, ptRt *PlaintextRingT) {
	switch pt := p.(type) {
	case *rlwe.Plaintext:
		ecd.ScaleDown(pt, ptRt)
	case *PlaintextMul:
		ecd.MulToRingT(pt, ptRt)
	case *PlaintextRingT:
		ptRt.Copy(pt.Plaintext)
	default:
		panic(fmt.Errorf("cannot SwitchToRingT: unsupported plaintext type (%T)", pt))
	}
}

// Decode decodes a any plaintext type and write the coefficients in coeffs.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul or if coeffs is not []uint64 or []int64.
func (ecd *encoder) Decode(p interface{}, coeffs interface{}) {

	var ptRt *PlaintextRingT
	var isInRingT bool
	if ptRt, isInRingT = p.(*PlaintextRingT); !isInRingT {
		ecd.SwitchToRingT(p, ecd.tmpPtRt)
		ptRt = ecd.tmpPtRt
	}

	ecd.params.RingT().NTT(ptRt.Value, ecd.tmpPoly)

	pos := ecd.indexMatrix
	tmp := ecd.tmpPoly.Coeffs[0]
	N := ecd.params.N()

	switch coeffs := coeffs.(type) {
	case []uint64:
		for i := 0; i < N; i++ {
			coeffs[i] = tmp[pos[i]]
		}
	case []int64:
		modulus := int64(ecd.params.T())
		modulusHalf := modulus >> 1
		var value int64
		for i := 0; i < N; i++ {
			if value = int64(tmp[ecd.indexMatrix[i]]); value >= modulusHalf {
				coeffs[i] = value - modulus
			} else {
				coeffs[i] = value
			}
		}
	default:
		panic("cannot Decode: coeffs.(type) must be either []uint64 or []int64")
	}
}

// DecodeUintNew decodes any plaintext type and returns the coefficients in a new []uint64.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeUintNew(p interface{}) (coeffs []uint64) {
	coeffs = make([]uint64, ecd.params.N())
	ecd.Decode(p, coeffs)
	return
}

// DecodeIntNew decodes any plaintext type and returns the coefficients in a new []int64. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeIntNew(p interface{}) (coeffs []int64) {
	coeffs = make([]int64, ecd.params.N())
	ecd.Decode(p, coeffs)
	return
}

// ShallowCopy creates a shallow copy of Encoder in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encoder can be used concurrently.
func (ecd *encoder) ShallowCopy() Encoder {
	return &encoder{
		params:      ecd.params,
		indexMatrix: ecd.indexMatrix,
		scaler:      NewRNSScaler(ecd.params.RingQ(), ecd.params.T()),
		tmpPoly:     ecd.params.RingQ().NewPoly(),
		tmpPtRt:     NewPlaintextRingT(ecd.params),
	}
}
