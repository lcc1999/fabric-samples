package advanced

import (
	"fmt"
	"math"
	"math/bits"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// SineType is the type of function used during the bootstrapping
// for the homomorphic modular reduction
type SineType uint64

func sin2pi2pi(x complex128) complex128 {
	return cmplx.Sin(6.283185307179586 * x) // 6.283185307179586
}

func cos2pi(x complex128) complex128 {
	return cmplx.Cos(6.283185307179586 * x)
}

// Sin and Cos are the two proposed functions for SineType.
// These trigonometric functions offer a good approximation of the function x mod 1 when the values are close to the origin.
const (
	CosDiscrete   = SineType(0) // Special approximation (Han and Ki) of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r); this method requires a minimum degree of 2*(K-1).
	SinContinuous = SineType(1) // Standard Chebyshev approximation of (1/2pi) * sin(2pix) on the full interval
	CosContinuous = SineType(2) // Standard Chebyshev approximation of pow((1/2pi), 1/2^r) * cos(2pi(x-0.25)/2^r) on the full interval
)

// EvalModLiteral a struct for the parameters of the EvalMod procedure.
// The EvalMod procedure goal is to homomorphically evaluate a modular reduction by Q[0] (the first prime of the moduli chain) on the encrypted plaintext.
// This struct is consumed by `NewEvalModPolyFromLiteral` to generate the `EvalModPoly` struct, which notably stores
// the coefficient of the polynomial approximating the function x mod Q[0].
type EvalModLiteral struct {
	LevelStart      int      // Starting level of EvalMod
	LogScale        int      // Log2 of the scaling factor used during EvalMod
	SineType        SineType // Chose between [Sin(2*pi*x)] or [cos(2*pi*x/r) with double angle formula]
	LogMessageRatio int      // Log2 of the ratio between Q0 and m, i.e. Q[0]/|m|
	K               int      // K parameter (interpolation in the range -K to K)
	SineDegree      int      // Degree of the interpolation
	DoubleAngle     int      // Number of rescale and double angle formula (only applies for cos and is ignored if sin is used)
	ArcSineDegree   int      // Degree of the Taylor arcsine composed with f(2*pi*x) (if zero then not used)
}

// EvalModPoly is a struct storing the parameters and polynomials approximating the function x mod Q[0] (the first prime of the moduli chain).
type EvalModPoly struct {
	levelStart      int
	logScale        int
	sineType        SineType
	LogMessageRatio int
	doubleAngle     int
	qDiff           float64
	scFac           float64
	sqrt2Pi         float64
	sinePoly        *ckks.Polynomial
	arcSinePoly     *ckks.Polynomial
	k               float64
}

// LevelStart returns the starting level of the EvalMod.
func (evp *EvalModPoly) LevelStart() int {
	return evp.levelStart
}

// ScalingFactor returns scaling factor used during the EvalMod.
func (evp *EvalModPoly) ScalingFactor() rlwe.Scale {
	return rlwe.NewScale(math.Exp2(float64(evp.logScale)))
}

// ScFac returns 1/2^r where r is the number of double angle evaluation.
func (evp *EvalModPoly) ScFac() float64 {
	return evp.scFac
}

// MessageRatio returns the pre-set ratio Q[0]/|m|.
func (evp *EvalModPoly) MessageRatio() float64 {
	return float64(uint(1 << evp.LogMessageRatio))
}

// K return the sine approximation range.
func (evp *EvalModPoly) K() float64 {
	return evp.k * evp.scFac
}

// QDiff return Q[0]/ClosetPow2
// This is the error introduced by the approximate division by Q[0].
func (evp *EvalModPoly) QDiff() float64 {
	return evp.qDiff
}

// NewEvalModPolyFromLiteral generates an EvalModPoly struct from the EvalModLiteral struct.
// The EvalModPoly struct is used by the `EvalModNew` method from the `Evaluator`, which
// homomorphically evaluates x mod Q[0] (the first prime of the moduli chain) on the ciphertext.
func NewEvalModPolyFromLiteral(params ckks.Parameters, evm EvalModLiteral) EvalModPoly {

	var arcSinePoly *ckks.Polynomial
	var sinePoly *ckks.Polynomial
	var sqrt2pi float64

	doubleAngle := evm.DoubleAngle
	if evm.SineType == SinContinuous {
		doubleAngle = 0
	}

	scFac := math.Exp2(float64(doubleAngle))

	K := float64(evm.K) / scFac

	Q := params.Q()[0]
	qDiff := float64(Q) / math.Exp2(math.Round(math.Log2(float64(Q))))

	if evm.ArcSineDegree > 0 {

		sqrt2pi = 1.0

		coeffs := make([]complex128, evm.ArcSineDegree+1)

		coeffs[1] = 0.15915494309189535 * complex(qDiff, 0)

		for i := 3; i < evm.ArcSineDegree+1; i += 2 {
			coeffs[i] = coeffs[i-2] * complex(float64(i*i-4*i+4)/float64(i*i-i), 0)
		}

		arcSinePoly = ckks.NewPoly(coeffs)

	} else {
		sqrt2pi = math.Pow(0.15915494309189535*qDiff, 1.0/scFac)
	}

	switch evm.SineType {
	case SinContinuous:

		sinePoly = ckks.Approximate(sin2pi2pi, -K, K, evm.SineDegree)
	case CosDiscrete:

		sinePoly = new(ckks.Polynomial)
		sinePoly.Coeffs = ApproximateCos(evm.K, evm.SineDegree, float64(uint(1<<evm.LogMessageRatio)), int(evm.DoubleAngle))
		sinePoly.MaxDeg = sinePoly.Degree()
		sinePoly.A = -K
		sinePoly.B = K
		sinePoly.Lead = true
		sinePoly.BasisType = ckks.Chebyshev

	case CosContinuous:

		sinePoly = ckks.Approximate(cos2pi, -K, K, evm.SineDegree)

	default:
		panic(fmt.Sprintf("invalid SineType: allowed types are SinContinuous, CosDiscrete and CosContinuous, but is %T", evm.SineType))
	}

	for i := range sinePoly.Coeffs {
		sinePoly.Coeffs[i] *= complex(sqrt2pi, 0)
	}

	return EvalModPoly{
		levelStart:      evm.LevelStart,
		logScale:        evm.LogScale,
		sineType:        evm.SineType,
		LogMessageRatio: evm.LogMessageRatio,
		doubleAngle:     doubleAngle,
		qDiff:           qDiff,
		scFac:           scFac,
		sqrt2Pi:         sqrt2pi,
		arcSinePoly:     arcSinePoly,
		sinePoly:        sinePoly,
		k:               K,
	}
}

// Depth returns the depth of the SineEval.
func (evm *EvalModLiteral) Depth() (depth int) {

	if evm.SineType == CosDiscrete { // this method requires a minimum degree of 2*K-1.
		depth += int(bits.Len64(uint64(utils.MaxInt(evm.SineDegree, 2*evm.K-1))))
	} else {
		depth += int(bits.Len64(uint64(evm.SineDegree)))
	}

	if evm.SineType != SinContinuous {
		depth += evm.DoubleAngle
	}

	depth += int(bits.Len64(uint64(evm.ArcSineDegree)))
	return depth
}
