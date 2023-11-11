package bfv

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// Scaler is an interface that rescales polynomial coefficients by a fraction t/Q.
type Scaler interface {
	// DivByQOverTRoundedLvl returns p1 scaled by a factor t/Q and mod t on the receiver p2.
	DivByQOverTRoundedLvl(level int, p1, p2 *ring.Poly)
	ScaleUpByQOverTLvl(level int, p1, p2 *ring.Poly)
}

// RNSScaler implements the Scaler interface by performing a scaling by t/Q in the RNS domain.
type RNSScaler struct {
	ringQ, ringT *ring.Ring

	buffQ *ring.Poly
	buffP *ring.Poly

	qHalf     []*big.Int // (q-1)/2
	qHalfModT []uint64   // (q-1)/2 mod t
	qInv      []uint64   //(q mod t)^-1 mod t
	tInvModQi []uint64   // t^-1 mod qi

	paramsQP []ring.ModUpConstants

	tDividesQ bool
}

// NewRNSScaler creates a new RNSScaler from t, the modulus under which the reconstruction is returned, the Ring in which the polynomial to reconstruct is represented.
func NewRNSScaler(ringQ *ring.Ring, T uint64) (rnss *RNSScaler) {

	moduli := ringQ.ModuliChain()

	if utils.IsInSliceUint64(T, moduli) && moduli[0] != T {
		panic("cannot NewRNSScaler: T must be Q[0] if T|Q")
	}

	rnss = new(RNSScaler)

	rnss.ringQ = ringQ

	rnss.buffQ = ringQ.NewPoly()

	rnss.ringT = new(ring.Ring)
	rnss.ringT.SubRings = []*ring.SubRing{{}}
	rnss.ringT.SubRings[0].N = ringQ.N()
	rnss.ringT.SubRings[0].Modulus = T
	rnss.ringT.SubRings[0].BRedConstant = ring.BRedConstant(T)
	rnss.ringT.SubRings[0].MRedConstant = ring.MRedConstant(T)
	rnss.buffP = rnss.ringT.NewPoly()

	rnss.tDividesQ = T == moduli[0]

	if !rnss.tDividesQ {

		rnss.tInvModQi = make([]uint64, len(moduli))
		for i, qi := range moduli {
			rnss.tInvModQi[i] = ring.MForm(ring.ModExp(T, qi-2, qi), qi, ringQ.SubRings[i].BRedConstant)
		}

		rnss.qHalf = make([]*big.Int, len(moduli))
		rnss.qInv = make([]uint64, len(moduli))
		rnss.qHalfModT = make([]uint64, len(moduli))
		rnss.paramsQP = make([]ring.ModUpConstants, len(moduli))

		bigQ := new(big.Int).SetUint64(1)
		tmp := new(big.Int)
		brc := ring.BRedConstant(T)
		TBig := ring.NewUint(T)
		for i, qi := range moduli {
			rnss.paramsQP[i] = ring.GenModUpConstants(moduli[:i+1], rnss.ringT.ModuliChain())

			bigQ.Mul(bigQ, ring.NewUint(qi))

			rnss.qInv[i] = tmp.Mod(bigQ, TBig).Uint64()
			rnss.qInv[i] = ring.ModExp(rnss.qInv[i], T-2, T)
			rnss.qInv[i] = ring.MForm(rnss.qInv[i], T, brc)

			rnss.qHalf[i] = new(big.Int).Set(bigQ)
			rnss.qHalf[i].Rsh(rnss.qHalf[i], 1)

			rnss.qHalfModT[i] = tmp.Mod(rnss.qHalf[i], TBig).Uint64()
		}
	}

	return
}

// DivByQOverTRoundedLvl returns p1 scaled by a factor t/Q and mod t on the receiver p2.
func (rnss *RNSScaler) DivByQOverTRoundedLvl(level int, p1Q, p2T *ring.Poly) {

	ringQ := rnss.ringQ.AtLevel(level)

	if level > 0 {
		if rnss.tDividesQ {
			ringQ.DivRoundByLastModulusMany(level, p1Q, rnss.buffQ, p2T)
		} else {

			ringT := rnss.ringT
			T := ringT.SubRings[0].Modulus
			p2tmp := p2T.Coeffs[0]
			p3tmp := rnss.buffP.Coeffs[0]
			qInv := T - rnss.qInv[level]
			qHalfModT := T - rnss.qHalfModT[level]

			// Multiplies P_{Q} by t and extend the basis from P_{Q} to t*(P_{Q}||P_{t})
			// Since the coefficients of P_{t} are multiplied by t, they are all zero,
			// hence the basis extension can be omitted
			ringQ.MulScalar(p1Q, T, rnss.buffQ)

			// Centers t*P_{Q} around (Q-1)/2 to round instead of floor during the division
			ringQ.AddScalarBigint(rnss.buffQ, rnss.qHalf[level], rnss.buffQ)

			// Extends the basis of (t*P_{Q} + (Q-1)/2) to (t*P_{t} + (Q-1)/2)
			ring.ModUpExact(rnss.buffQ.Coeffs[:level+1], rnss.buffP.Coeffs, ringQ, ringT, rnss.paramsQP[level])

			// Computes [Q^{-1} * (t*P_{t} - (t*P_{Q} - ((Q-1)/2 mod t)))] mod t which returns round(t/Q * P_{Q}) mod t
			ringT.SubRings[0].AddScalarLazyThenMulScalarMontgomery(p3tmp, qHalfModT, qInv, p2tmp)
		}
	} else {
		if rnss.tDividesQ {
			copy(p2T.Coeffs[0], p1Q.Coeffs[0])
		} else {
			// In this case lvl = 0 and T < Q. This step has a maximum precision of 53 bits, however
			// since |Q| < 62 bits, and min(logN) = 10, then |<s, e>| > 10 bits, hence there is no
			// possible case where |T| > 51 bits & lvl = 0 that does not lead to an overflow of
			// the error when decrypting.
			qOverT := float64(ringQ.SubRings[0].Modulus) / float64(rnss.ringT.SubRings[0].Modulus)
			tmp0, tmp1 := p2T.Coeffs[0], p1Q.Coeffs[0]
			N := ringQ.N()
			for i := 0; i < N; i++ {
				tmp0[i] = uint64(float64(tmp1[i])/qOverT + 0.5)
			}
		}
	}
}

// ScaleUpByQOverTLvl takes a Poly pIn in ringT, scales its coefficients up by (Q/T) mod Q, and writes the result on pOut.
func (rnss *RNSScaler) ScaleUpByQOverTLvl(level int, pIn, pOut *ring.Poly) {

	if !rnss.tDividesQ {
		ScaleUpTCoprimeWithQVecLvl(level, rnss.ringQ, rnss.ringT, rnss.tInvModQi, rnss.buffQ.Coeffs[0], pIn, pOut)
	} else {
		ScaleUpTIsQ0VecLvl(level, rnss.ringQ, pIn, pOut)
	}
}

// ScaleUpTCoprimeWithQVecLvl takes a Poly pIn in ringT, scales its coefficients up by (Q/T) mod Q, and writes the result in a
// Poly pOut in ringQ.
func ScaleUpTCoprimeWithQVecLvl(level int, ringQ, ringT *ring.Ring, tInvModQi, buffN []uint64, pIn, pOut *ring.Poly) {

	qModTmontgomery := ring.MForm(new(big.Int).Mod(ringQ.ModulusAtLevel[level], ring.NewUint(ringT.SubRings[0].Modulus)).Uint64(), ringT.SubRings[0].Modulus, ringT.SubRings[0].BRedConstant)

	tHalf := ringT.SubRings[0].Modulus >> 1

	// (x * Q + T/2) mod T
	ringT.SubRings[0].MulScalarMontgomeryThenAddScalar(pIn.Coeffs[0], tHalf, qModTmontgomery, buffN)

	// (x * T^-1 - T/2) mod Qi
	for i, s := range ringQ.SubRings[:level+1] {
		p0tmp := buffN
		p1tmp := pOut.Coeffs[i]
		rescaleParams := s.Modulus - tInvModQi[i]
		tHalfNegQi := s.Modulus - ring.BRedAdd(tHalf, s.Modulus, s.BRedConstant)

		s.AddScalarLazyThenMulScalarMontgomery(p0tmp, tHalfNegQi, rescaleParams, p1tmp)
	}
}

// ScaleUpTIsQ0VecLvl takes a Poly pIn in ringT, scales its coefficients up by (Q/T) mod Q, and writes the result on a
// Poly pOut in ringQ.
// T is in this case assumed to be the first prime in the moduli chain.
func ScaleUpTIsQ0VecLvl(level int, ringQ *ring.Ring, pIn, pOut *ring.Poly) {

	// Q/T mod T
	tmp := new(big.Int)
	tmp.Quo(ringQ.ModulusAtLevel[level], ringQ.ModulusAtLevel[0])
	QOverTMont := ring.MForm(tmp.Mod(tmp, new(big.Int).SetUint64(ringQ.SubRings[0].Modulus)).Uint64(), ringQ.SubRings[0].Modulus, ringQ.SubRings[0].BRedConstant)

	// pOut = Q/T * pIn
	ringQ.SubRings[0].MulScalarMontgomery(pIn.Coeffs[0], QOverTMont, pOut.Coeffs[0])

	for i := 1; i < level+1; i++ {
		ring.ZeroVec(pOut.Coeffs[i])
	}
}
