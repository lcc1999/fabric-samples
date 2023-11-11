package drlwe

import (
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// CKSProtocol is the structure storing the parameters and and precomputations for the collective key-switching protocol.
type CKSProtocol struct {
	params          rlwe.Parameters
	sigmaSmudging   float64
	gaussianSampler *ring.GaussianSampler
	basisExtender   *ring.BasisExtender
	tmpQP           ringqp.Poly
	tmpDelta        *ring.Poly
}

// ShallowCopy creates a shallow copy of CKSProtocol in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// CKSProtocol can be used concurrently.
func (cks *CKSProtocol) ShallowCopy() *CKSProtocol {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	params := cks.params

	return &CKSProtocol{
		params:          params,
		gaussianSampler: ring.NewGaussianSampler(prng, params.RingQ(), cks.sigmaSmudging, int(6*cks.sigmaSmudging)),
		basisExtender:   cks.basisExtender.ShallowCopy(),
		tmpQP:           params.RingQP().NewPoly(),
		tmpDelta:        params.RingQ().NewPoly(),
	}
}

// CKSShare is a type for the CKS protocol shares.
type CKSShare struct {
	Value *ring.Poly
}

// CKSCRP is a type for common reference polynomials in the CKS protocol.
type CKSCRP ring.Poly

// Level returns the level of the target share.
func (ckss *CKSShare) Level() int {
	return ckss.Value.Level()
}

// MarshalBinary encodes a CKS share on a slice of bytes.
func (ckss *CKSShare) MarshalBinary() (data []byte, err error) {
	return ckss.Value.MarshalBinary()
}

// UnmarshalBinary decodes marshaled CKS share on the target CKS share.
func (ckss *CKSShare) UnmarshalBinary(data []byte) (err error) {
	ckss.Value = new(ring.Poly)
	return ckss.Value.UnmarshalBinary(data)
}

// NewCKSProtocol creates a new CKSProtocol that will be used to perform a collective key-switching on a ciphertext encrypted under a collective public-key, whose
// secret-shares are distributed among j parties, re-encrypting the ciphertext under another public-key, whose secret-shares are also known to the
// parties.
func NewCKSProtocol(params rlwe.Parameters, sigmaSmudging float64) *CKSProtocol {
	cks := new(CKSProtocol)
	cks.params = params
	cks.sigmaSmudging = sigmaSmudging
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}
	cks.gaussianSampler = ring.NewGaussianSampler(prng, params.RingQ(), sigmaSmudging, int(6*sigmaSmudging))

	if cks.params.RingP() != nil {
		cks.basisExtender = ring.NewBasisExtender(params.RingQ(), params.RingP())
	}
	cks.tmpQP = params.RingQP().NewPoly()
	cks.tmpDelta = params.RingQ().NewPoly()
	return cks
}

// AllocateShare allocates the shares of the CKSProtocol
func (cks *CKSProtocol) AllocateShare(level int) *CKSShare {
	return &CKSShare{cks.params.RingQ().AtLevel(level).NewPoly()}
}

// SampleCRP samples a common random polynomial to be used in the CKS protocol from the provided
// common reference string.
func (cks *CKSProtocol) SampleCRP(level int, crs CRS) CKSCRP {
	ringQ := cks.params.RingQ().AtLevel(level)
	crp := ringQ.NewPoly()
	ring.NewUniformSampler(crs, ringQ).Read(crp)
	return CKSCRP(*crp)
}

// GenShare computes a party's share in the CKS protocol from secret-key skInput to secret-key skOutput.
// ct is the rlwe.Ciphertext to keyswitch. Note that ct.Value[0] is not used by the function and can be nil/zero.
func (cks *CKSProtocol) GenShare(skInput, skOutput *rlwe.SecretKey, ct *rlwe.Ciphertext, shareOut *CKSShare) {

	c1 := ct.Value[1]

	levelQ := utils.MinInt(shareOut.Value.Level(), c1.Level())
	levelP := cks.params.PCount() - 1

	shareOut.Value.Resize(levelQ)

	ringQP := cks.params.RingQP().AtLevel(levelQ, levelP)
	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	ringQ.Sub(skInput.Value.Q, skOutput.Value.Q, cks.tmpDelta)

	ct1 := c1
	if !ct.IsNTT {
		ringQ.NTTLazy(c1, cks.tmpQP.Q)
		ct1 = cks.tmpQP.Q
	}

	// a * (skIn - skOut) mod Q
	ringQ.MulCoeffsMontgomeryLazy(ct1, cks.tmpDelta, shareOut.Value)

	if ringP != nil {
		// P * a * (skIn - skOut) mod QP (mod P = 0)
		ringQ.MulScalarBigint(shareOut.Value, ringP.ModulusAtLevel[levelP], shareOut.Value)
	}

	if !ct.IsNTT {
		// InvNTT(P * a * (skIn - skOut)) mod QP (mod P = 0)
		ringQ.INTTLazy(shareOut.Value, shareOut.Value)

		// Samples e in Q
		cks.gaussianSampler.Read(cks.tmpQP.Q)

		if ringP != nil {
			// Extend e to P (assumed to have norm < qi)
			ringQP.ExtendBasisSmallNormAndCenter(cks.tmpQP.Q, levelP, nil, cks.tmpQP.P)
		}

		// InvNTT(P * a * (skIn - skOut) + e) mod QP (mod P = e)
		ringQ.Add(shareOut.Value, cks.tmpQP.Q, shareOut.Value)

		if ringP != nil {
			// InvNTT(P * a * (skIn - skOut) + e) * (1/P) mod QP (mod P = e)
			cks.basisExtender.ModDownQPtoQ(levelQ, levelP, shareOut.Value, cks.tmpQP.P, shareOut.Value)
		}

	} else {
		// Sample e in Q
		cks.gaussianSampler.Read(cks.tmpQP.Q)

		if ringP != nil {
			// Extend e to P (assumed to have norm < qi)
			ringQP.ExtendBasisSmallNormAndCenter(cks.tmpQP.Q, levelP, nil, cks.tmpQP.P)
		}

		// Takes the error to the NTT domain
		ringQ.INTT(shareOut.Value, shareOut.Value)

		// P * a * (skIn - skOut) + e mod Q (mod P = 0, so P = e)
		ringQ.Add(shareOut.Value, cks.tmpQP.Q, shareOut.Value)

		if ringP != nil {
			// (P * a * (skIn - skOut) + e) * (1/P) mod QP (mod P = e)
			cks.basisExtender.ModDownQPtoQ(levelQ, levelP, shareOut.Value, cks.tmpQP.P, shareOut.Value)
		}

		ringQ.NTT(shareOut.Value, shareOut.Value)

	}
}

// AggregateShares is the second part of the unique round of the CKSProtocol protocol. Upon receiving the j-1 elements each party computes :
//
// [ctx[0] + sum((skInput_i - skOutput_i) * ctx[0] + e_i), ctx[1]]
func (cks *CKSProtocol) AggregateShares(share1, share2, shareOut *CKSShare) {
	if share1.Level() != share2.Level() || share1.Level() != shareOut.Level() {
		panic("shares levels do not match")
	}

	cks.params.RingQ().AtLevel(share1.Level()).Add(share1.Value, share2.Value, shareOut.Value)
}

// KeySwitch performs the actual keyswitching operation on a ciphertext ct and put the result in ctOut
func (cks *CKSProtocol) KeySwitch(ctIn *rlwe.Ciphertext, combined *CKSShare, ctOut *rlwe.Ciphertext) {

	level := ctIn.Level()

	if ctIn != ctOut {

		ctOut.Resize(ctIn.Degree(), level)

		ring.CopyLvl(level, ctIn.Value[1], ctOut.Value[1])

		ctOut.MetaData = ctIn.MetaData
	}

	cks.params.RingQ().AtLevel(level).Add(ctIn.Value[0], combined.Value, ctOut.Value[0])
}
