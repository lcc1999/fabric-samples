package rlwe

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

// TestParams is a set of test parameters for the correctness of the rlwe package.
var TestParams = []ParametersLiteral{TestPN10QP27, TestPN11QP54, TestPN12QP109, TestPN13QP218, TestPN14QP438, TestPN15QP880, TestPN16QP240, TestPN17QP360}

func testString(params Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/logQ=%d/logP=%d/#Qi=%d/#Pi=%d/%s",
		opname,
		params.LogN(),
		params.LogQ(),
		params.LogP(),
		params.QCount(),
		params.PCount(),
		params.RingType())
}

func TestRLWE(t *testing.T) {

	var err error

	defaultParams := TestParams // the default test runs for ring degree N=2^12, 2^13, 2^14, 2^15
	if testing.Short() {
		defaultParams = TestParams[:2] // the short test suite runs for ring degree N=2^12, 2^13
	}

	if *flagParamString != "" {
		var jsonParams ParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			t.Fatal(err)
		}
		defaultParams = []ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, defaultParam := range defaultParams[:] {

		var params Parameters
		if params, err = NewParametersFromLiteral(defaultParam); err != nil {
			t.Fatal(err)
		}

		kgen := NewKeyGenerator(params)

		for _, testSet := range []func(kgen KeyGenerator, t *testing.T){
			testGenKeyPair,
			testSwitchKeyGen,
			testEncryptor,
			testDecryptor,
			testKeySwitcher,
			testKeySwitchDimension,
			testMerge,
			testExpand,
			testMarshaller,
		} {
			testSet(kgen, t)
			runtime.GC()
		}
	}
}

func testGenKeyPair(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	sk, pk := kgen.GenKeyPair()

	t.Run("CheckMetaData", func(t *testing.T) {
		require.True(t, pk.MetaData.Equal(MetaData{IsNTT: true, IsMontgomery: true}))
	})

	// Checks that the secret-key has exactly params.h non-zero coefficients
	t.Run(testString(params, "SK"), func(t *testing.T) {

		skINTT := NewSecretKey(params)

		if params.PCount() > 0 {
			params.RingP().AtLevel(sk.LevelP()).INTT(sk.Value.P, skINTT.Value.P)
			for i := range skINTT.Value.P.Coeffs {
				var zeros int
				for j := range skINTT.Value.P.Coeffs[i] {
					if skINTT.Value.P.Coeffs[i][j] == 0 {
						zeros++
					}
				}
				require.Equal(t, params.ringP.N(), zeros+params.h)
			}
		}

		params.RingQ().AtLevel(sk.LevelQ()).INTT(sk.Value.Q, skINTT.Value.Q)
		for i := range skINTT.Value.Q.Coeffs {
			var zeros int
			for j := range skINTT.Value.Q.Coeffs[i] {
				if skINTT.Value.Q.Coeffs[i][j] == 0 {
					zeros++
				}
			}
			require.Equal(t, params.ringQ.N(), zeros+params.h)
		}

	})

	// Checks that sum([-as + e, a] + [as])) <= N * 6 * sigma
	t.Run(testString(params, "PK"), func(t *testing.T) {

		log2Bound := bits.Len64(params.NoiseBound() * uint64(params.N()))

		if params.PCount() > 0 {

			ringQP := params.RingQP()

			ringQP.MulCoeffsMontgomeryThenAdd(sk.Value, pk.Value[1], pk.Value[0])
			ringQP.INTT(pk.Value[0], pk.Value[0])
			ringQP.IMForm(pk.Value[0], pk.Value[0])

			require.GreaterOrEqual(t, log2Bound, params.RingQ().Log2OfInnerSum(pk.Value[0].Q))
			require.GreaterOrEqual(t, log2Bound, params.RingP().Log2OfInnerSum(pk.Value[0].P))
		} else {

			ringQ := params.RingQ()

			ringQ.MulCoeffsMontgomeryThenAdd(sk.Value.Q, pk.Value[1].Q, pk.Value[0].Q)
			ringQ.INTT(pk.Value[0].Q, pk.Value[0].Q)
			ringQ.IMForm(pk.Value[0].Q, pk.Value[0].Q)

			require.GreaterOrEqual(t, log2Bound, params.RingQ().Log2OfInnerSum(pk.Value[0].Q))
		}

	})

}

func testSwitchKeyGen(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	// Checks that switching keys are en encryption under the output key
	// of the RNS decomposition of the input key by
	// 1) Decrypting the RNS decomposed input key
	// 2) Reconstructing the key
	// 3) Checking that the difference with the input key has a small norm
	t.Run(testString(params, "SWKGen"), func(t *testing.T) {
		skIn := kgen.GenSecretKey()
		skOut := kgen.GenSecretKey()
		levelQ, levelP := params.MaxLevelQ(), params.MaxLevelP()
		decompPW2 := params.DecompPw2(levelQ, levelP)
		decompRNS := params.DecompRNS(levelQ, levelP)

		// Generates Decomp([-asIn + w*P*sOut + e, a])
		swk := NewSwitchingKey(params, params.MaxLevelQ(), params.MaxLevelP())
		kgen.(*keyGenerator).genSwitchingKey(skIn.Value.Q, skOut, swk)

		require.Equal(t, decompRNS*decompPW2, len(swk.Value)*len(swk.Value[0])) // checks that decomposition size is correct

		log2Bound := bits.Len64(params.NoiseBound() * uint64(params.N()*len(swk.Value)))

		require.True(t, SwitchingKeyIsCorrect(swk, skIn, skOut, params, log2Bound))
	})
}

func testEncryptor(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	sk, pk := kgen.GenKeyPair()

	t.Run(testString(params, "Encrypt/Pk/MaxLevel"), func(t *testing.T) {
		ringQ := params.RingQ()
		plaintext := NewPlaintext(params, params.MaxLevel())
		plaintext.IsNTT = true
		encryptor := NewEncryptor(params, pk)
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		ringQ.MulCoeffsMontgomeryThenAdd(ciphertext.Value[1], sk.Value.Q, ciphertext.Value[0])
		if ciphertext.IsNTT {
			ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		}
		require.GreaterOrEqual(t, 9+params.LogN(), ringQ.Log2OfInnerSum(ciphertext.Value[0]))
	})

	t.Run(testString(params, "Encrypt/Pk/MinLevel"), func(t *testing.T) {
		ringQ := params.RingQ().AtLevel(0)
		plaintext := NewPlaintext(params, 0)
		plaintext.IsNTT = true
		encryptor := NewEncryptor(params, pk)
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		ringQ.MulCoeffsMontgomeryThenAdd(ciphertext.Value[1], sk.Value.Q, ciphertext.Value[0])
		if ciphertext.IsNTT {
			ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		}
		require.GreaterOrEqual(t, 9+params.LogN(), ringQ.Log2OfInnerSum(ciphertext.Value[0]))
	})

	t.Run(testString(params, "Encrypt/Pk/ShallowCopy"), func(t *testing.T) {
		enc1 := NewEncryptor(params, pk)
		enc2 := enc1.ShallowCopy()
		pkEnc1, pkEnc2 := enc1.(*pkEncryptor), enc2.(*pkEncryptor)
		require.True(t, pkEnc1.params.Equals(pkEnc2.params))
		require.True(t, pkEnc1.pk == pkEnc2.pk)
		require.False(t, (pkEnc1.basisextender == pkEnc2.basisextender) && (pkEnc1.basisextender != nil) && (pkEnc2.basisextender != nil))
		require.False(t, pkEnc1.encryptorBuffers == pkEnc2.encryptorBuffers)
		require.False(t, pkEnc1.ternarySampler == pkEnc2.ternarySampler)
		require.False(t, pkEnc1.gaussianSampler == pkEnc2.gaussianSampler)
	})

	t.Run(testString(params, "Encrypt/Sk/MaxLevel"), func(t *testing.T) {
		ringQ := params.RingQ()
		plaintext := NewPlaintext(params, params.MaxLevel())
		plaintext.IsNTT = true
		encryptor := NewEncryptor(params, sk)
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		ringQ.MulCoeffsMontgomeryThenAdd(ciphertext.Value[1], sk.Value.Q, ciphertext.Value[0])
		if ciphertext.IsNTT {
			ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		}
		require.GreaterOrEqual(t, 5+params.LogN(), ringQ.Log2OfInnerSum(ciphertext.Value[0]))
	})

	t.Run(testString(params, "Encrypt/Sk/MinLevel"), func(t *testing.T) {
		ringQ := params.RingQ().AtLevel(0)
		plaintext := NewPlaintext(params, 0)
		plaintext.IsNTT = true
		encryptor := NewEncryptor(params, sk)
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		ringQ.MulCoeffsMontgomeryThenAdd(ciphertext.Value[1], sk.Value.Q, ciphertext.Value[0])
		if ciphertext.IsNTT {
			ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		}
		require.GreaterOrEqual(t, 5+params.LogN(), ringQ.Log2OfInnerSum(ciphertext.Value[0]))
	})

	t.Run(testString(params, "Encrypt/Sk/PRNG"), func(t *testing.T) {
		ringQ := params.RingQ()
		plaintext := NewPlaintext(params, params.MaxLevel())
		plaintext.IsNTT = true
		encryptor := NewPRNGEncryptor(params, sk)
		ciphertextCRP := &Ciphertext{Value: []*ring.Poly{ringQ.NewPoly()}}

		prng1, _ := utils.NewKeyedPRNG([]byte{'a', 'b', 'c'})
		prng2, _ := utils.NewKeyedPRNG([]byte{'a', 'b', 'c'})

		encryptor.WithPRNG(prng1).Encrypt(plaintext, ciphertextCRP)

		require.Equal(t, plaintext.MetaData, ciphertextCRP.MetaData)
		require.Equal(t, plaintext.Level(), ciphertextCRP.Level())

		samplerQ := ring.NewUniformSampler(prng2, ringQ)
		c1 := samplerQ.ReadNew()
		ciphertext := Ciphertext{Value: []*ring.Poly{ciphertextCRP.Value[0], c1}, MetaData: ciphertextCRP.MetaData}

		ringQ.MulCoeffsMontgomeryThenAdd(ciphertext.Value[1], sk.Value.Q, ciphertext.Value[0])
		if ciphertext.IsNTT {
			ringQ.INTT(ciphertext.Value[0], ciphertext.Value[0])
		}
		require.GreaterOrEqual(t, 5+params.LogN(), ringQ.Log2OfInnerSum(ciphertext.Value[0]))
	})

	t.Run(testString(params, "Encrypt/Sk/ShallowCopy"), func(t *testing.T) {
		enc1 := NewEncryptor(params, sk)
		enc2 := enc1.ShallowCopy()
		skEnc1, skEnc2 := enc1.(*skEncryptor), enc2.(*skEncryptor)
		require.True(t, skEnc1.params.Equals(skEnc2.params))
		require.True(t, skEnc1.sk == skEnc2.sk)
		require.False(t, (skEnc1.basisextender == skEnc2.basisextender) && (skEnc1.basisextender != nil) && (skEnc2.basisextender != nil))
		require.False(t, skEnc1.encryptorBuffers == skEnc2.encryptorBuffers)
		require.False(t, skEnc1.ternarySampler == skEnc2.ternarySampler)
		require.False(t, skEnc1.gaussianSampler == skEnc2.gaussianSampler)
	})

	t.Run(testString(params, "Encrypt/WithKey/Sk->Sk"), func(t *testing.T) {
		sk2 := kgen.GenSecretKey()
		enc1 := NewEncryptor(params, sk)
		enc2 := enc1.WithKey(sk2)
		skEnc1, skEnc2 := enc1.(*skEncryptor), enc2.(*skEncryptor)
		require.True(t, skEnc1.params.Equals(skEnc2.params))
		require.True(t, skEnc1.sk.Value.Equals(sk.Value))
		require.True(t, skEnc2.sk.Value.Equals(sk2.Value))
		require.True(t, skEnc1.basisextender == skEnc2.basisextender)
		require.True(t, skEnc1.encryptorBuffers == skEnc2.encryptorBuffers)
		require.True(t, skEnc1.ternarySampler == skEnc2.ternarySampler)
		require.True(t, skEnc1.gaussianSampler == skEnc2.gaussianSampler)
	})
}

func testDecryptor(kgen KeyGenerator, t *testing.T) {
	params := kgen.(*keyGenerator).params
	sk := kgen.GenSecretKey()
	encryptor := NewEncryptor(params, sk)
	decryptor := NewDecryptor(params, sk)

	t.Run(testString(params, "Decrypt/MaxLevel"), func(t *testing.T) {
		ringQ := params.RingQ()
		plaintext := NewPlaintext(params, params.MaxLevel())
		plaintext.IsNTT = true
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		decryptor.Decrypt(ciphertext, plaintext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		if plaintext.IsNTT {
			ringQ.INTT(plaintext.Value, plaintext.Value)
		}
		require.GreaterOrEqual(t, 5+params.LogN(), ringQ.Log2OfInnerSum(plaintext.Value))
	})

	t.Run(testString(params, "Encrypt/MinLevel"), func(t *testing.T) {
		ringQ := params.RingQ().AtLevel(0)
		plaintext := NewPlaintext(params, 0)
		plaintext.IsNTT = true
		ciphertext := NewCiphertext(params, 1, plaintext.Level())
		encryptor.Encrypt(plaintext, ciphertext)
		decryptor.Decrypt(ciphertext, plaintext)
		require.Equal(t, plaintext.Level(), ciphertext.Level())
		require.Equal(t, plaintext.IsNTT, ciphertext.IsNTT)
		if plaintext.IsNTT {
			ringQ.INTT(plaintext.Value, plaintext.Value)
		}
		require.GreaterOrEqual(t, 5+params.LogN(), ringQ.Log2OfInnerSum(plaintext.Value))
	})
}

func testKeySwitcher(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	t.Run(testString(params, "KeySwitch"), func(t *testing.T) {

		sk := kgen.GenSecretKey()
		skOut := kgen.GenSecretKey()
		eval := NewEvaluator(params, nil)

		ringQ := params.RingQ()

		levelQ := params.MaxLevel()

		pt := NewPlaintext(params, levelQ)
		pt.IsNTT = true
		ct := NewCiphertext(params, 1, pt.Level())

		NewEncryptor(params, sk).Encrypt(pt, ct)

		// Test that Dec(KS(Enc(ct, sk), skOut), skOut) has a small norm
		swk := kgen.GenSwitchingKey(sk, skOut)

		eval.SwitchKeys(ct, swk, ct)

		NewDecryptor(params, skOut).Decrypt(ct, pt)

		if pt.IsNTT {
			ringQ.INTT(pt.Value, pt.Value)
		}

		require.GreaterOrEqual(t, 11+params.LogN(), ringQ.Log2OfInnerSum(pt.Value))
	})
}

func testKeySwitchDimension(kgen KeyGenerator, t *testing.T) {

	paramsLargeDim := kgen.(*keyGenerator).params

	t.Run("KeySwitchDimension", func(t *testing.T) {

		var Q []uint64
		if len(paramsLargeDim.Q()) > 1 {
			Q = paramsLargeDim.Q()[:1]
		} else {
			Q = paramsLargeDim.Q()
		}

		paramsSmallDim, err := NewParametersFromLiteral(ParametersLiteral{
			LogN:     paramsLargeDim.LogN() - 1,
			Q:        Q,
			P:        []uint64{0x1ffffffff6c80001, 0x1ffffffff6140001}, // some other P to test that the modulus is correctly extended in the keygen
			Sigma:    DefaultSigma,
			RingType: paramsLargeDim.RingType(),
		})

		assert.Nil(t, err)

		t.Run(testString(paramsLargeDim, "LargeToSmall"), func(t *testing.T) {

			ringQSmallDim := paramsSmallDim.RingQ()

			kgenLargeDim := NewKeyGenerator(paramsLargeDim)
			skLargeDim := kgenLargeDim.GenSecretKey()
			kgenSmallDim := NewKeyGenerator(paramsSmallDim)
			skSmallDim := kgenSmallDim.GenSecretKey()

			swk := kgenLargeDim.GenSwitchingKey(skLargeDim, skSmallDim)

			plaintext := NewPlaintext(paramsLargeDim, paramsLargeDim.MaxLevel())
			plaintext.IsNTT = true
			encryptor := NewEncryptor(paramsLargeDim, skLargeDim)
			ctLargeDim := NewCiphertext(paramsLargeDim, 1, plaintext.Level())
			encryptor.Encrypt(plaintext, ctLargeDim)

			eval := NewEvaluator(paramsLargeDim, nil)

			ctSmallDim := NewCiphertext(paramsSmallDim, 1, paramsSmallDim.MaxLevel())

			// skLarge -> skSmall embedded in N
			eval.SwitchKeys(ctLargeDim, swk, ctSmallDim)

			// Decrypts with smaller dimension key
			ringQSmallDim.MulCoeffsMontgomeryThenAdd(ctSmallDim.Value[1], skSmallDim.Value.Q, ctSmallDim.Value[0])

			if ctSmallDim.IsNTT {
				ringQSmallDim.INTT(ctSmallDim.Value[0], ctSmallDim.Value[0])
			}

			require.GreaterOrEqual(t, 11+paramsSmallDim.LogN(), ringQSmallDim.Log2OfInnerSum(ctSmallDim.Value[0]))
		})

		t.Run(testString(paramsLargeDim, "SmallToLarge"), func(t *testing.T) {

			ringQLargeDim := paramsLargeDim.RingQ().AtLevel(0)

			kgenLargeDim := NewKeyGenerator(paramsLargeDim)
			skLargeDim := kgenLargeDim.GenSecretKey()
			kgenSmallDim := NewKeyGenerator(paramsSmallDim)
			skSmallDim := kgenSmallDim.GenSecretKey()

			swk := kgenLargeDim.GenSwitchingKey(skSmallDim, skLargeDim)

			plaintext := NewPlaintext(paramsSmallDim, paramsSmallDim.MaxLevel())
			plaintext.IsNTT = true

			encryptor := NewEncryptor(paramsSmallDim, skSmallDim)
			ctSmallDim := NewCiphertext(paramsSmallDim, 1, plaintext.Level())
			encryptor.Encrypt(plaintext, ctSmallDim)

			ctLargeDim := NewCiphertext(paramsLargeDim, 1, plaintext.Level())

			eval := NewEvaluator(paramsLargeDim, nil)

			eval.SwitchKeys(ctSmallDim, swk, ctLargeDim)

			// Decrypts with smaller dimension key
			ringQLargeDim.MulCoeffsMontgomeryThenAdd(ctLargeDim.Value[1], skLargeDim.Value.Q, ctLargeDim.Value[0])

			if ctLargeDim.IsNTT {
				ringQLargeDim.INTT(ctLargeDim.Value[0], ctLargeDim.Value[0])
			}

			require.GreaterOrEqual(t, 11+paramsSmallDim.LogN(), ringQLargeDim.Log2OfInnerSum(ctLargeDim.Value[0]))
		})
	})
}

func testMerge(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	t.Run(testString(params, "Merge"), func(t *testing.T) {

		kgen := NewKeyGenerator(params)
		sk := kgen.GenSecretKey()
		encryptor := NewEncryptor(params, sk)
		decryptor := NewDecryptor(params, sk)
		pt := NewPlaintext(params, params.MaxLevel())
		N := params.N()

		for i := 0; i < pt.Level()+1; i++ {
			for j := 0; j < N; j++ {
				pt.Value.Coeffs[i][j] = (1 << 30) + uint64(j)*(1<<20)
			}
		}

		params.RingQ().NTT(pt.Value, pt.Value)
		pt.IsNTT = true

		ciphertexts := make(map[int]*Ciphertext)
		slotIndex := make(map[int]bool)
		for i := 0; i < N; i += params.N() / 16 {
			ciphertexts[i] = NewCiphertext(params, 1, params.MaxLevel())
			encryptor.Encrypt(pt, ciphertexts[i])
			slotIndex[i] = true
		}

		// Rotation Keys
		galEls := params.GaloisElementsForMerge()
		rtks := kgen.GenRotationKeys(galEls, sk)

		eval := NewEvaluator(params, &EvaluationKey{Rtks: rtks})

		ciphertext := eval.Merge(ciphertexts)

		decryptor.Decrypt(ciphertext, pt)

		if pt.IsNTT {
			params.RingQ().INTT(pt.Value, pt.Value)
		}

		bound := uint64(params.N() * params.N())

		Q := params.RingQ().ModuliChain()

		for i := 0; i < pt.Level()+1; i++ {

			qi := Q[i]
			qiHalf := qi >> 1

			for j, c := range pt.Value.Coeffs[i] {

				if c >= qiHalf {
					c = qi - c
				}

				// Checks that the empty slots have a small noise
				if _, ok := slotIndex[j]; !ok {

					if c > bound {
						t.Fatal(i, j, c)
					}
				}
			}
		}
	})
}

func testExpand(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	IsNTT := false

	t.Run(testString(params, "Expand"), func(t *testing.T) {

		kgen := NewKeyGenerator(params)
		sk := kgen.GenSecretKey()
		encryptor := NewEncryptor(params, sk)
		decryptor := NewDecryptor(params, sk)
		pt := NewPlaintext(params, params.MaxLevel())

		logN := 4
		logGap := 1
		gap := 1 << logGap

		values := make([]uint64, params.N())

		scale := 1 << 22

		for i := 0; i < 1<<logN; i++ { // embeds even coefficients only
			values[i] = uint64(scale * i)
		}

		for i := 0; i < pt.Level()+1; i++ {
			copy(pt.Value.Coeffs[i], values)
		}

		if IsNTT {
			params.RingQ().NTT(pt.Value, pt.Value)
			pt.IsNTT = true
		}

		ctIn := NewCiphertext(params, 1, params.MaxLevel())
		encryptor.Encrypt(pt, ctIn)

		// Rotation Keys
		galEls := params.GaloisElementForExpand(logN)

		rtks := kgen.GenRotationKeys(galEls, sk)

		eval := NewEvaluator(params, &EvaluationKey{Rtks: rtks})

		ciphertexts := eval.Expand(ctIn, logN, logGap)

		bound := uint64(params.N() * params.N())

		Q := params.RingQ().ModuliChain()

		for i := range ciphertexts {

			decryptor.Decrypt(ciphertexts[i], pt)

			if pt.IsNTT {
				params.RingQ().INTT(pt.Value, pt.Value)
			}

			for j := 0; j < pt.Level()+1; j++ {

				qi := Q[j]
				qiHalf := qi >> 1

				for k, c := range pt.Value.Coeffs[j] {

					if c >= qiHalf {
						c = qi - c
					}

					if k != 0 {
						require.Greater(t, bound, c)
					} else {
						require.InDelta(t, 0, math.Abs(float64(values[i*gap])-float64(c))/float64(scale), 0.01)
					}
				}
			}
		}
	})
}

func testMarshaller(kgen KeyGenerator, t *testing.T) {

	params := kgen.(*keyGenerator).params

	sk, pk := kgen.GenKeyPair()

	t.Run(testString(params, "Marshaller/Parameters/Binary"), func(t *testing.T) {
		bytes, err := params.MarshalBinary()
		assert.Nil(t, err)
		var p Parameters
		err = p.UnmarshalBinary(bytes)
		assert.Nil(t, err)
		assert.Equal(t, params, p)
		assert.Equal(t, params.RingQ(), p.RingQ())
	})

	t.Run(testString(params, "Marshaller/Parameters/JSON"), func(t *testing.T) {
		// checks that parameters can be marshalled without error
		data, err := json.Marshal(params)
		assert.Nil(t, err)
		assert.NotNil(t, data)

		// checks that Parameters can be unmarshalled without error
		var rlweParams Parameters
		err = json.Unmarshal(data, &rlweParams)
		assert.Nil(t, err)
		assert.True(t, params.Equals(rlweParams))
	})

	t.Run("Marshaller/MetaData", func(t *testing.T) {
		m := MetaData{Scale: NewScaleModT(1, 65537), IsNTT: true, IsMontgomery: true}

		data, err := m.MarshalBinary()
		assert.Nil(t, err)
		assert.NotNil(t, data)

		mHave := MetaData{}

		assert.Nil(t, mHave.UnmarshalBinary(data))

		require.True(t, m.Equal(mHave))
	})

	t.Run(testString(params, "Marshaller/Ciphertext"), func(t *testing.T) {

		prng, _ := utils.NewPRNG()

		for degree := 0; degree < 4; degree++ {
			t.Run(fmt.Sprintf("degree=%d", degree), func(t *testing.T) {
				ciphertextWant := NewCiphertextRandom(prng, params, degree, params.MaxLevel())

				marshalledCiphertext, err := ciphertextWant.MarshalBinary()
				require.NoError(t, err)

				ciphertextTest := new(Ciphertext)
				require.NoError(t, ciphertextTest.UnmarshalBinary(marshalledCiphertext))

				require.Equal(t, ciphertextWant.Degree(), ciphertextTest.Degree())
				require.Equal(t, ciphertextWant.Level(), ciphertextTest.Level())

				for i := range ciphertextWant.Value {
					require.True(t, params.RingQ().Equal(ciphertextWant.Value[i], ciphertextTest.Value[i]))
				}
			})
		}
	})

	t.Run(testString(params, "Marshaller/Sk"), func(t *testing.T) {

		marshalledSk, err := sk.MarshalBinary()
		require.NoError(t, err)

		skTest := new(SecretKey)
		err = skTest.UnmarshalBinary(marshalledSk)
		require.NoError(t, err)

		require.True(t, sk.Value.Equals(skTest.Value))
	})

	t.Run(testString(params, "Marshaller/Pk"), func(t *testing.T) {

		marshalledPk, err := pk.MarshalBinary()
		require.NoError(t, err)

		pkTest := new(PublicKey)
		err = pkTest.UnmarshalBinary(marshalledPk)
		require.NoError(t, err)

		require.True(t, pk.Equals(pkTest))
	})

	t.Run(testString(params, "Marshaller/EvaluationKey"), func(t *testing.T) {

		evalKey := kgen.GenRelinearizationKey(sk, 3)
		data, err := evalKey.MarshalBinary()
		require.NoError(t, err)

		resEvalKey := new(RelinearizationKey)
		err = resEvalKey.UnmarshalBinary(data)
		require.NoError(t, err)

		require.True(t, evalKey.Equals(resEvalKey))
	})

	t.Run(testString(params, "Marshaller/SwitchingKey"), func(t *testing.T) {

		skOut := kgen.GenSecretKey()

		switchingKey := kgen.GenSwitchingKey(sk, skOut)
		data, err := switchingKey.MarshalBinary()
		require.NoError(t, err)

		resSwitchingKey := new(SwitchingKey)
		err = resSwitchingKey.UnmarshalBinary(data)
		require.NoError(t, err)

		require.True(t, switchingKey.Equals(resSwitchingKey))
	})

	t.Run(testString(params, "Marshaller/RotationKey"), func(t *testing.T) {

		rots := []int{1, -1, 63, -63}
		galEls := []uint64{}
		if params.RingType() == ring.Standard {
			galEls = append(galEls, params.GaloisElementForRowRotation())
		}

		for _, n := range rots {
			galEls = append(galEls, params.GaloisElementForColumnRotationBy(n))
		}

		rotationKey := kgen.GenRotationKeys(galEls, sk)

		data, err := rotationKey.MarshalBinary()
		require.NoError(t, err)

		resRotationKey := new(RotationKeySet)
		err = resRotationKey.UnmarshalBinary(data)
		require.NoError(t, err)

		rotationKey.Equals(resRotationKey)
	})
}
