package ckks

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/cmplx"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var flagLongTest = flag.Bool("long", false, "run the long test suite (all parameters + secure bootstrapping). Overrides -short and requires -timeout=0.")
var flagPostQuantum = flag.Bool("pq", false, "run post quantum test suite (does not run non-PQ parameters).")
var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")

var minPrec float64 = 15.0

func GetTestName(params Parameters, opname string) string {
	return fmt.Sprintf("%s/RingType=%s/logN=%d/logQP=%d/LogSlots=%d/levels=%d/#Pi=%d/Decomp=%d",
		opname,
		params.RingType(),
		params.LogN(),
		params.LogQP(),
		params.LogSlots(),
		params.MaxLevel()+1,
		params.PCount(),
		params.DecompRNS(params.MaxLevelQ(), params.MaxLevelP()))
}

type testContext struct {
	params      Parameters
	ringQ       *ring.Ring
	ringP       *ring.Ring
	prng        utils.PRNG
	encoder     Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	rlk         *rlwe.RelinearizationKey
	encryptorPk rlwe.Encryptor
	encryptorSk rlwe.Encryptor
	decryptor   rlwe.Decryptor
	evaluator   Evaluator
}

func TestCKKS(t *testing.T) {

	var err error

	var testParams []ParametersLiteral
	switch {
	case *flagParamString != "": // the custom test suite reads the parameters from the -params flag
		testParams = append(testParams, ParametersLiteral{})
		if err = json.Unmarshal([]byte(*flagParamString), &testParams[0]); err != nil {
			t.Fatal(err)
		}
	case *flagLongTest:
		for _, pls := range [][]ParametersLiteral{
			DefaultParams,
			DefaultConjugateInvariantParams,
			DefaultPostQuantumParams,
			DefaultPostQuantumConjugateInvariantParams} {
			testParams = append(testParams, pls...)
		}
	case *flagPostQuantum && testing.Short():
		testParams = append(DefaultPostQuantumParams[:2], DefaultPostQuantumConjugateInvariantParams[:2]...)
	case *flagPostQuantum:
		testParams = append(DefaultPostQuantumParams[:4], DefaultPostQuantumConjugateInvariantParams[:4]...)
	case testing.Short():
		testParams = append(DefaultParams[:2], DefaultConjugateInvariantParams[:2]...)
	default:
		testParams = append(DefaultParams[:4], DefaultConjugateInvariantParams[:4]...)
	}

	for _, paramsLiteral := range testParams[:] {

		var params Parameters
		if params, err = NewParametersFromLiteral(paramsLiteral); err != nil {
			t.Fatal(err)
		}

		var tc *testContext
		if tc, err = genTestParams(params); err != nil {
			t.Fatal(err)
		}

		for _, testSet := range []func(tc *testContext, t *testing.T){
			testParameters,
			testEncoder,
			testEncryptor,
			testEvaluatorAdd,
			testEvaluatorSub,
			testEvaluatorRescale,
			testEvaluatorAddConst,
			testEvaluatorMultByConst,
			testEvaluatorMultByConstThenAdd,
			testEvaluatorMul,
			testEvaluatorMulThenAdd,
			testFunctions,
			testDecryptPublic,
			testEvaluatePoly,
			testChebyshevInterpolator,
			testSwitchKeys,
			testBridge,
			testAutomorphisms,
			testInnerSum,
			testReplicate,
			testLinearTransform,
			testMarshaller,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}
}

func genTestParams(defaultParam Parameters) (tc *testContext, err error) {

	tc = new(testContext)

	tc.params = defaultParam

	tc.kgen = NewKeyGenerator(tc.params)

	tc.sk, tc.pk = tc.kgen.GenKeyPair()

	tc.ringQ = defaultParam.RingQ()
	if tc.params.PCount() != 0 {
		tc.ringP = defaultParam.RingP()
		tc.rlk = tc.kgen.GenRelinearizationKey(tc.sk, 1)
	}

	if tc.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	tc.encoder = NewEncoder(tc.params)

	tc.encryptorPk = NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = NewEncryptor(tc.params, tc.sk)
	tc.decryptor = NewDecryptor(tc.params, tc.sk)

	tc.evaluator = NewEvaluator(tc.params, rlwe.EvaluationKey{Rlk: tc.rlk})

	return tc, nil

}

func newTestVectors(tc *testContext, encryptor rlwe.Encryptor, a, b complex128, t *testing.T) (values []complex128, plaintext *rlwe.Plaintext, ciphertext *rlwe.Ciphertext) {

	logSlots := tc.params.LogSlots()

	values = make([]complex128, 1<<logSlots)

	switch tc.params.RingType() {
	case ring.Standard:
		for i := 0; i < 1<<logSlots; i++ {
			values[i] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
		}
	case ring.ConjugateInvariant:
		for i := 0; i < 1<<logSlots; i++ {
			values[i] = complex(utils.RandFloat64(real(a), real(b)), 0)
		}
	default:
		panic("invalid ring type")
	}

	values[0] = 0.607538 + 0i

	plaintext = tc.encoder.EncodeNew(values, tc.params.MaxLevel(), tc.params.DefaultScale(), logSlots)

	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	return values, plaintext, ciphertext
}

func randomConst(tp ring.Type, a, b complex128) (constant complex128) {
	switch tp {
	case ring.Standard:
		constant = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
	case ring.ConjugateInvariant:
		constant = complex(utils.RandFloat64(real(a), real(b)), 0)
	default:
		panic("invalid ring type")
	}
	return
}

func verifyTestVectors(params Parameters, encoder Encoder, decryptor rlwe.Decryptor, valuesWant []complex128, element interface{}, logSlots int, bound float64, t *testing.T) {

	precStats := GetPrecisionStats(params, encoder, decryptor, valuesWant, element, logSlots, bound)

	if *printPrecisionStats {
		t.Log(precStats.String())
	}

	require.GreaterOrEqual(t, precStats.MeanPrecision.Real, minPrec)
	require.GreaterOrEqual(t, precStats.MeanPrecision.Imag, minPrec)
}

func testParameters(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Parameters/NewParameters"), func(t *testing.T) {
		params, err := NewParametersFromLiteral(ParametersLiteral{
			LogN:     4,
			LogQ:     []int{60, 60},
			LogP:     []int{60},
			LogScale: 0,
		})
		require.NoError(t, err)
		require.Equal(t, ring.Standard, params.RingType())   // Default ring type should be standard
		require.Equal(t, rlwe.DefaultSigma, params.Sigma())  // Default error std should be rlwe.DefaultSigma
		require.Equal(t, params.LogN()-1, params.LogSlots()) // Default number of slots should be N/2
	})

	t.Run(GetTestName(tc.params, "Parameters/StandardRing"), func(t *testing.T) {
		params, err := tc.params.StandardParameters()
		switch tc.params.RingType() {
		case ring.Standard:
			require.True(t, params.Equals(tc.params))
			require.NoError(t, err)
		case ring.ConjugateInvariant:
			require.Equal(t, params.LogN(), tc.params.LogN()+1)
			require.Equal(t, params.LogSlots(), tc.params.LogSlots())
			require.NoError(t, err)
		default:
			t.Fatal("invalid RingType")
		}
	})
}

func testEncoder(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Encoder/Encode"), func(t *testing.T) {

		values, plaintext, _ := newTestVectors(tc, nil, -1-1i, 1+1i, t)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, plaintext, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Encoder/EncodeCoeffs"), func(t *testing.T) {

		slots := tc.params.N()

		valuesWant := make([]float64, slots)

		for i := 0; i < slots; i++ {
			valuesWant[i] = utils.RandFloat64(-1, 1)
		}

		valuesWant[0] = 0.607538

		plaintext := tc.encoder.EncodeCoeffsNew(valuesWant, tc.params.MaxLevel(), tc.params.DefaultScale())

		valuesTest := tc.encoder.DecodeCoeffs(plaintext)

		var meanprec float64

		for i := range valuesWant {
			meanprec += math.Abs(valuesTest[i] - valuesWant[i])
		}

		meanprec /= float64(slots)

		if *printPrecisionStats {
			t.Logf("\nMean    precision : %.2f \n", math.Log2(1/meanprec))
		}

		require.GreaterOrEqual(t, math.Log2(1/meanprec), minPrec)
	})

}

func testEncryptor(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Encryptor/Encrypt/key=pk"), func(t *testing.T) {
		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorPk, -1-1i, 1+1i, t)
		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Encryptor/Encrypt/key=sk"), func(t *testing.T) {
		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Encryptor/WithPRNG/Encrypt"), func(t *testing.T) {
		lvl := tc.params.MaxLevel()
		enc := NewPRNGEncryptor(tc.params, tc.sk)
		prng1, _ := utils.NewKeyedPRNG([]byte{'l'})
		prng2, _ := utils.NewKeyedPRNG([]byte{'l'})
		sampler := ring.NewUniformSampler(prng2, tc.ringQ)
		values1, pt, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		ciphertext := enc.WithPRNG(prng1).EncryptNew(pt)
		c1Want := sampler.AtLevel(lvl).ReadNew()
		assert.True(t, c1Want.Equals(ciphertext.Value[1]))
		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext, tc.params.LogSlots(), 0, t)
	})

}

func testEvaluatorAdd(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/Add/CtCt"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i]
		}

		tc.evaluator.Add(ciphertext1, ciphertext2, ciphertext1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/AddNew/CtCt"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i]
		}

		ciphertext3 := tc.evaluator.AddNew(ciphertext1, ciphertext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext3, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Add/CtPlain"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, plaintext2, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i]
		}

		tc.evaluator.Add(ciphertext1, plaintext2, ciphertext1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/AddNew/CtPlain"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, plaintext2, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i]
		}

		ciphertext3 := tc.evaluator.AddNew(ciphertext1, plaintext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext3, tc.params.LogSlots(), 0, t)
	})

}

func testEvaluatorSub(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/Sub/CtCt"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] -= values2[i]
		}

		tc.evaluator.Sub(ciphertext1, ciphertext2, ciphertext1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/SubNew/CtCt"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] -= values2[i]
		}

		ciphertext3 := tc.evaluator.SubNew(ciphertext1, ciphertext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext3, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Sub/CtPlain"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, plaintext2, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		valuesTest := make([]complex128, len(values1))
		for i := range values1 {
			valuesTest[i] = values1[i] - values2[i]
		}

		tc.evaluator.Sub(ciphertext1, plaintext2, ciphertext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, valuesTest, ciphertext2, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/SubNew/CtPlain"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, plaintext2, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		valuesTest := make([]complex128, len(values1))
		for i := range values1 {
			valuesTest[i] = values1[i] - values2[i]
		}

		ciphertext3 := tc.evaluator.SubNew(ciphertext1, plaintext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, valuesTest, ciphertext3, tc.params.LogSlots(), 0, t)
	})

}

func testEvaluatorRescale(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/Rescale/Single"), func(t *testing.T) {

		if tc.params.MaxLevel() < 2 {
			t.Skip("skipping test for params max level < 2")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := tc.ringQ.SubRings[ciphertext.Level()].Modulus

		tc.evaluator.MultByConst(ciphertext, constant, ciphertext)

		ciphertext.Scale = ciphertext.Scale.Mul(rlwe.NewScale(constant))

		if err := tc.evaluator.Rescale(ciphertext, tc.params.DefaultScale(), ciphertext); err != nil {
			t.Fatal(err)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/Rescale/Many"), func(t *testing.T) {

		if tc.params.MaxLevel() < 2 {
			t.Skip("skipping test for params max level < 2")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		nbRescales := tc.params.MaxLevel()
		if nbRescales > 5 {
			nbRescales = 5
		}

		for i := 0; i < nbRescales; i++ {
			constant := tc.ringQ.SubRings[ciphertext.Level()-i].Modulus
			tc.evaluator.MultByConst(ciphertext, constant, ciphertext)
			ciphertext.Scale = ciphertext.Scale.Mul(rlwe.NewScale(constant))
		}

		if err := tc.evaluator.Rescale(ciphertext, tc.params.DefaultScale(), ciphertext); err != nil {
			t.Fatal(err)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testEvaluatorAddConst(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/AddConst"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), -1+1i, -1+1i)

		for i := range values {
			values[i] += constant
		}

		tc.evaluator.AddConst(ciphertext, constant, ciphertext)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testEvaluatorMultByConst(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/MultByConst"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), -1+1i, -1+1i)

		for i := range values {
			values[i] *= constant
		}

		tc.evaluator.MultByConst(ciphertext, constant, ciphertext)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})

}

func testEvaluatorMultByConstThenAdd(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/MultByConstThenAdd"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		constant := randomConst(tc.params.RingType(), -1+1i, -1+1i)

		for i := range values1 {
			values2[i] += (constant * values1[i])
		}

		tc.evaluator.MultByConstThenAdd(ciphertext1, constant, ciphertext2)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext2, tc.params.LogSlots(), 0, t)
	})

}

func testEvaluatorMul(tc *testContext, t *testing.T) {

	t.Run("Evaluator/Mul", func(t *testing.T) {

		t.Run(GetTestName(tc.params, "ct0*pt->ct0"), func(t *testing.T) {

			values1, plaintext1, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values1[i]
			}

			tc.evaluator.MulRelin(ciphertext1, plaintext1, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "pt*ct0->ct0"), func(t *testing.T) {

			values1, plaintext1, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values1[i]
			}

			tc.evaluator.MulRelin(ciphertext1, plaintext1, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*pt->ct1"), func(t *testing.T) {

			values1, plaintext1, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values1[i]
			}

			ciphertext2 := tc.evaluator.MulRelinNew(ciphertext1, plaintext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext2, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct1->ct0"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values2[i] *= values1[i]
			}

			tc.evaluator.MulRelin(ciphertext1, ciphertext2, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct1->ct0 (degree 0)"), func(t *testing.T) {

			values1, plaintext1, _ := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values2[i] *= values1[i]
			}

			ciphertext1 := &rlwe.Ciphertext{Value: []*ring.Poly{plaintext1.Value}, MetaData: plaintext1.MetaData}

			tc.evaluator.MulRelin(ciphertext1, ciphertext2, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct1->ct1"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values2[i] *= values1[i]
			}

			tc.evaluator.MulRelin(ciphertext1, ciphertext2, ciphertext2)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext2, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct1->ct2"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values2[i] *= values1[i]
			}

			ciphertext3 := tc.evaluator.MulRelinNew(ciphertext1, ciphertext2)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext3, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct0->ct0"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values1[i]
			}

			tc.evaluator.MulRelin(ciphertext1, ciphertext1, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "ct0*ct0->ct1"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values1[i]
			}

			ciphertext2 := tc.evaluator.MulRelinNew(ciphertext1, ciphertext1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext2, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "Relinearize(ct0*ct1->ct0)"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values1[i] *= values2[i]
			}

			tc.evaluator.Mul(ciphertext1, ciphertext2, ciphertext1)
			require.Equal(t, ciphertext1.Degree(), 2)
			tc.evaluator.Relinearize(ciphertext1, ciphertext1)
			require.Equal(t, ciphertext1.Degree(), 1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
		})

		t.Run(GetTestName(tc.params, "Relinearize(ct0*ct1->ct1)"), func(t *testing.T) {

			values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
			values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

			for i := range values1 {
				values2[i] *= values1[i]
			}

			tc.evaluator.Mul(ciphertext1, ciphertext2, ciphertext2)
			require.Equal(t, ciphertext2.Degree(), 2)
			tc.evaluator.Relinearize(ciphertext2, ciphertext2)
			require.Equal(t, ciphertext2.Degree(), 1)

			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values2, ciphertext2, tc.params.LogSlots(), 0, t)
		})
	})
}

func testEvaluatorMulThenAdd(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/ct1*pt0->ct0"), func(t *testing.T) {

		values1, plaintext1, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values1[i] * values2[i]
		}

		tc.evaluator.MulRelinThenAdd(ciphertext2, plaintext1, ciphertext1)

		require.Equal(t, ciphertext1.Degree(), 1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulRelinThenAdd/ct1*ct1->ct0"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i] * values2[i]
		}

		tc.evaluator.MulRelinThenAdd(ciphertext2, ciphertext2, ciphertext1)

		require.Equal(t, ciphertext1.Degree(), 1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/ct0*ct1->ct2"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] = values1[i] * values2[i]
		}

		ciphertext3 := NewCiphertext(tc.params, 2, ciphertext1.Level())

		ciphertext3.Scale = ciphertext1.Scale.Mul(ciphertext2.Scale)

		tc.evaluator.MulThenAdd(ciphertext1, ciphertext2, ciphertext3)

		require.Equal(t, ciphertext3.Degree(), 2)

		tc.evaluator.Relinearize(ciphertext3, ciphertext3)

		require.Equal(t, ciphertext3.Degree(), 1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext3, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Evaluator/MulThenAdd/ct1*ct1->ct0"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)
		values2, _, ciphertext2 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values1 {
			values1[i] += values2[i] * values2[i]
		}

		tc.evaluator.MulThenAdd(ciphertext2, ciphertext2, ciphertext1)

		require.Equal(t, ciphertext1.Degree(), 2)

		tc.evaluator.Relinearize(ciphertext1, ciphertext1)

		require.Equal(t, ciphertext1.Degree(), 1)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})
}

func testFunctions(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Evaluator/Inverse"), func(t *testing.T) {

		if tc.params.MaxLevel() < 7 {
			t.Skip("skipping test for params max level < 7")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, 0.1+0i, 1+0i, t)

		n := 7

		for i := range values {
			values[i] = 1.0 / values[i]
		}

		var err error
		if ciphertext, err = tc.evaluator.InverseNew(ciphertext, n); err != nil {
			t.Fatal(err)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testEvaluatePoly(tc *testContext, t *testing.T) {

	var err error

	t.Run(GetTestName(tc.params, "EvaluatePoly/PolySingle/Exp"), func(t *testing.T) {

		if tc.params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		coeffs := []complex128{
			1.0,
			1.0,
			1.0 / 2,
			1.0 / 6,
			1.0 / 24,
			1.0 / 120,
			1.0 / 720,
			1.0 / 5040,
		}

		poly := NewPoly(coeffs)

		for i := range values {
			values[i] = cmplx.Exp(values[i])
		}

		if ciphertext, err = tc.evaluator.EvaluatePoly(ciphertext, poly, ciphertext.Scale); err != nil {
			t.Fatal(err)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "EvaluatePoly/PolyVector/Exp"), func(t *testing.T) {

		if tc.params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		coeffs := []complex128{
			1.0,
			1.0,
			1.0 / 2,
			1.0 / 6,
			1.0 / 24,
			1.0 / 120,
			1.0 / 720,
			1.0 / 5040,
		}

		poly := NewPoly(coeffs)

		slotIndex := make(map[int][]int)
		idx := make([]int, tc.params.Slots()>>1)
		for i := 0; i < tc.params.Slots()>>1; i++ {
			idx[i] = 2 * i
		}

		slotIndex[0] = idx

		valuesWant := make([]complex128, tc.params.Slots())
		for _, j := range idx {
			valuesWant[j] = cmplx.Exp(values[j])
		}

		if ciphertext, err = tc.evaluator.EvaluatePolyVector(ciphertext, []*Polynomial{poly}, tc.encoder, slotIndex, ciphertext.Scale); err != nil {
			t.Fatal(err)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, valuesWant, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testChebyshevInterpolator(tc *testContext, t *testing.T) {

	var err error

	t.Run(GetTestName(tc.params, "ChebyshevInterpolator/Sin"), func(t *testing.T) {

		if tc.params.MaxLevel() < 5 {
			t.Skip("skipping test for params max level < 5")
		}

		eval := tc.evaluator

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		poly := Approximate(cmplx.Sin, -1.5, 1.5, 15)

		eval.MultByConst(ciphertext, 2/(poly.B-poly.A), ciphertext)
		eval.AddConst(ciphertext, (-poly.A-poly.B)/(poly.B-poly.A), ciphertext)
		if err = eval.Rescale(ciphertext, tc.params.DefaultScale(), ciphertext); err != nil {
			t.Fatal(err)

		}

		if ciphertext, err = eval.EvaluatePoly(ciphertext, poly, ciphertext.Scale); err != nil {
			t.Fatal(err)

		}

		for i := range values {
			values[i] = cmplx.Sin(values[i])
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testDecryptPublic(tc *testContext, t *testing.T) {

	var err error

	t.Run(GetTestName(tc.params, "DecryptPublic/Sin"), func(t *testing.T) {

		if tc.params.MaxLevel() < 5 {
			t.Skip("skipping test for params max level < 5")
		}

		eval := tc.evaluator

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1, 1, t)

		poly := Approximate(cmplx.Sin, -1.5, 1.5, 15)

		for i := range values {
			values[i] = cmplx.Sin(values[i])
		}

		eval.MultByConst(ciphertext, 2/(poly.B-poly.A), ciphertext)
		eval.AddConst(ciphertext, (-poly.A-poly.B)/(poly.B-poly.A), ciphertext)
		if err := eval.Rescale(ciphertext, tc.params.DefaultScale(), ciphertext); err != nil {
			t.Fatal(err)

		}

		if ciphertext, err = eval.EvaluatePoly(ciphertext, poly, ciphertext.Scale); err != nil {
			t.Fatal(err)

		}

		plaintext := tc.decryptor.DecryptNew(ciphertext)

		valuesHave := tc.encoder.Decode(plaintext, tc.params.LogSlots())

		verifyTestVectors(tc.params, tc.encoder, nil, values, valuesHave, tc.params.LogSlots(), 0, t)

		sigma := tc.encoder.GetErrSTDCoeffDomain(values, valuesHave, plaintext.Scale)

		valuesHave = tc.encoder.DecodePublic(plaintext, tc.params.LogSlots(), sigma)

		verifyTestVectors(tc.params, tc.encoder, nil, values, valuesHave, tc.params.LogSlots(), 0, t)
	})
}

func testSwitchKeys(tc *testContext, t *testing.T) {

	sk2 := tc.kgen.GenSecretKey()
	decryptorSk2 := NewDecryptor(tc.params, sk2)
	switchingKey := tc.kgen.GenSwitchingKey(tc.sk, sk2)

	t.Run(GetTestName(tc.params, "SwitchKeys"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		tc.evaluator.SwitchKeys(ciphertext, switchingKey, ciphertext)

		verifyTestVectors(tc.params, tc.encoder, decryptorSk2, values, ciphertext, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "SwitchKeysNew"), func(t *testing.T) {

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		ciphertext = tc.evaluator.SwitchKeysNew(ciphertext, switchingKey)

		verifyTestVectors(tc.params, tc.encoder, decryptorSk2, values, ciphertext, tc.params.LogSlots(), 0, t)
	})
}

func testBridge(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Bridge"), func(t *testing.T) {

		if tc.params.RingType() != ring.ConjugateInvariant {
			t.Skip("only tested for params.RingType() == ring.ConjugateInvariant")
		}

		ciParams := tc.params
		var err error
		if _, err = ciParams.StandardParameters(); err != nil {
			t.Fatalf("all Conjugate Invariant parameters should have a standard counterpart but got: %f", err)
		}

		// Create equivalent parameters with RingStandard ring type and different auxiliary modulus P
		stdParamsLit := ciParams.ParametersLiteral()
		stdParamsLit.LogN = ciParams.LogN() + 1
		stdParamsLit.P = []uint64{0x1ffffffff6c80001, 0x1ffffffff6140001} // Assigns new P to ensure that independence from auxiliary P is tested
		stdParamsLit.RingType = ring.Standard
		stdParams, err := NewParametersFromLiteral(stdParamsLit)
		require.Nil(t, err)

		stdKeyGen := NewKeyGenerator(stdParams)
		stdSK := stdKeyGen.GenSecretKey()
		stdDecryptor := NewDecryptor(stdParams, stdSK)
		stdEncoder := NewEncoder(stdParams)
		stdEvaluator := NewEvaluator(stdParams, rlwe.EvaluationKey{Rlk: nil, Rtks: nil})

		swkCtR, swkRtC := stdKeyGen.GenSwitchingKeysForRingSwap(stdSK, tc.sk)

		switcher, err := NewDomainSwitcher(stdParams, swkCtR, swkRtC)
		if err != nil {
			t.Fatal(err)
		}

		evalStandar := NewEvaluator(stdParams, rlwe.EvaluationKey{})

		values, _, ctCI := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		stdCTHave := NewCiphertext(stdParams, ctCI.Degree(), ctCI.Level())

		switcher.RealToComplex(evalStandar, ctCI, stdCTHave)

		verifyTestVectors(stdParams, stdEncoder, stdDecryptor, values, stdCTHave, stdParams.LogSlots(), 0, t)

		stdCTImag := stdEvaluator.MultByConstNew(stdCTHave, 1i)
		stdEvaluator.Add(stdCTHave, stdCTImag, stdCTHave)

		ciCTHave := NewCiphertext(ciParams, 1, stdCTHave.Level())
		switcher.ComplexToReal(evalStandar, stdCTHave, ciCTHave)

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values, ciCTHave, ciParams.LogSlots(), 0, t)
	})
}

func testAutomorphisms(tc *testContext, t *testing.T) {

	params := tc.params

	rots := []int{0, 1, -1, 4, -4, 63, -63}
	var rotKey *rlwe.RotationKeySet

	if tc.params.PCount() != 0 {
		rotKey = tc.kgen.GenRotationKeysForRotations(rots, params.RingType() == ring.Standard, tc.sk)
	}

	evaluator := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

	t.Run(GetTestName(params, "Conjugate"), func(t *testing.T) {

		if params.RingType() != ring.Standard {
			t.Skip("Conjugate not defined in real-CKKS")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values {
			values[i] = complex(real(values[i]), -imag(values[i]))
		}

		evaluator.Conjugate(ciphertext, ciphertext)

		verifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(params, "ConjugateNew"), func(t *testing.T) {

		if params.RingType() != ring.Standard {
			t.Skip("Conjugate not defined in real-CKKS")
		}

		values, _, ciphertext := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for i := range values {
			values[i] = complex(real(values[i]), -imag(values[i]))
		}

		ciphertext = evaluator.ConjugateNew(ciphertext)

		verifyTestVectors(params, tc.encoder, tc.decryptor, values, ciphertext, params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "Rotate"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		ciphertext2 := NewCiphertext(tc.params, ciphertext1.Degree(), ciphertext1.Level())

		for _, n := range rots {
			evaluator.Rotate(ciphertext1, n, ciphertext2)
			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, utils.RotateComplex128Slice(values1, n), ciphertext2, tc.params.LogSlots(), 0, t)
		}
	})

	t.Run(GetTestName(tc.params, "RotateNew"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		for _, n := range rots {
			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, utils.RotateComplex128Slice(values1, n), evaluator.RotateNew(ciphertext1, n), tc.params.LogSlots(), 0, t)
		}

	})

	t.Run(GetTestName(tc.params, "RotateHoisted"), func(t *testing.T) {

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		ciphertexts := evaluator.RotateHoistedNew(ciphertext1, rots)

		for _, n := range rots {
			verifyTestVectors(tc.params, tc.encoder, tc.decryptor, utils.RotateComplex128Slice(values1, n), ciphertexts[n], tc.params.LogSlots(), 0, t)
		}
	})
}

func testInnerSum(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "InnerSum"), func(t *testing.T) {

		batch := 512
		n := tc.params.Slots() / batch

		rotKey := tc.kgen.GenRotationKeysForRotations(tc.params.RotationsForInnerSum(batch, n), false, tc.sk)
		eval := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		eval.InnerSum(ciphertext1, batch, n, ciphertext1)

		tmp0 := make([]complex128, len(values1))
		copy(tmp0, values1)

		for i := 1; i < n; i++ {

			tmp1 := utils.RotateComplex128Slice(tmp0, i*batch)

			for j := range values1 {
				values1[j] += tmp1[j]
			}
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)

	})

	t.Run(GetTestName(tc.params, "Average"), func(t *testing.T) {

		logBatch := 9
		batch := 1 << logBatch
		n := tc.params.Slots() / batch

		rotKey := tc.kgen.GenRotationKeysForRotations(tc.params.RotationsForInnerSum(batch, n), false, tc.sk)
		eval := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		eval.Average(ciphertext1, logBatch, ciphertext1)

		tmp0 := make([]complex128, len(values1))
		copy(tmp0, values1)

		for i := 1; i < n; i++ {

			tmp1 := utils.RotateComplex128Slice(tmp0, i*batch)

			for j := range values1 {
				values1[j] += tmp1[j]
			}
		}

		for i := range values1 {
			values1[i] /= complex(float64(n), 0)
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)

	})
}

func testReplicate(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Replicate"), func(t *testing.T) {

		batch := 3
		n := 15

		rotKey := tc.kgen.GenRotationKeysForRotations(tc.params.RotationsForReplicate(batch, n), false, tc.sk)
		eval := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		eval.Replicate(ciphertext1, batch, n, ciphertext1)

		tmp0 := make([]complex128, len(values1))
		copy(tmp0, values1)

		for i := 1; i < n; i++ {

			tmp1 := utils.RotateComplex128Slice(tmp0, i*-batch)

			for j := range values1 {
				values1[j] += tmp1[j]
			}
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)

	})
}

func testLinearTransform(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "LinearTransform/BSGS"), func(t *testing.T) {

		params := tc.params

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		diagMatrix := make(map[int][]complex128)

		diagMatrix[-15] = make([]complex128, params.Slots())
		diagMatrix[-4] = make([]complex128, params.Slots())
		diagMatrix[-1] = make([]complex128, params.Slots())
		diagMatrix[0] = make([]complex128, params.Slots())
		diagMatrix[1] = make([]complex128, params.Slots())
		diagMatrix[2] = make([]complex128, params.Slots())
		diagMatrix[3] = make([]complex128, params.Slots())
		diagMatrix[4] = make([]complex128, params.Slots())
		diagMatrix[15] = make([]complex128, params.Slots())

		for i := 0; i < params.Slots(); i++ {
			diagMatrix[-15][i] = 1
			diagMatrix[-4][i] = 1
			diagMatrix[-1][i] = 1
			diagMatrix[0][i] = 1
			diagMatrix[1][i] = 1
			diagMatrix[2][i] = 1
			diagMatrix[3][i] = 1
			diagMatrix[4][i] = 1
			diagMatrix[15][i] = 1
		}

		linTransf := GenLinearTransformBSGS(tc.encoder, diagMatrix, params.MaxLevel(), rlwe.NewScale(params.Q()[params.MaxLevel()]), 2.0, params.logSlots)

		rots := linTransf.Rotations()

		rotKey := tc.kgen.GenRotationKeysForRotations(rots, false, tc.sk)

		eval := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

		eval.LinearTransform(ciphertext1, linTransf, []*rlwe.Ciphertext{ciphertext1})

		tmp := make([]complex128, params.Slots())
		copy(tmp, values1)

		for i := 0; i < params.Slots(); i++ {
			values1[i] += tmp[(i-15+params.Slots())%params.Slots()]
			values1[i] += tmp[(i-4+params.Slots())%params.Slots()]
			values1[i] += tmp[(i-1+params.Slots())%params.Slots()]
			values1[i] += tmp[(i+1)%params.Slots()]
			values1[i] += tmp[(i+2)%params.Slots()]
			values1[i] += tmp[(i+3)%params.Slots()]
			values1[i] += tmp[(i+4)%params.Slots()]
			values1[i] += tmp[(i+15)%params.Slots()]
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})

	t.Run(GetTestName(tc.params, "LinearTransform/Naive"), func(t *testing.T) {

		params := tc.params

		values1, _, ciphertext1 := newTestVectors(tc, tc.encryptorSk, -1-1i, 1+1i, t)

		diagMatrix := make(map[int][]complex128)

		diagMatrix[-1] = make([]complex128, params.Slots())
		diagMatrix[0] = make([]complex128, params.Slots())

		for i := 0; i < params.Slots(); i++ {
			diagMatrix[-1][i] = 1
			diagMatrix[0][i] = 1
		}

		linTransf := GenLinearTransform(tc.encoder, diagMatrix, params.MaxLevel(), rlwe.NewScale(params.Q()[params.MaxLevel()]), params.LogSlots())

		rots := linTransf.Rotations()

		rotKey := tc.kgen.GenRotationKeysForRotations(rots, false, tc.sk)

		eval := tc.evaluator.WithKey(rlwe.EvaluationKey{Rlk: tc.rlk, Rtks: rotKey})

		eval.LinearTransform(ciphertext1, linTransf, []*rlwe.Ciphertext{ciphertext1})

		tmp := make([]complex128, params.Slots())
		copy(tmp, values1)

		for i := 0; i < params.Slots(); i++ {
			values1[i] += tmp[(i-1+params.Slots())%params.Slots()]
		}

		verifyTestVectors(tc.params, tc.encoder, tc.decryptor, values1, ciphertext1, tc.params.LogSlots(), 0, t)
	})
}

func testMarshaller(tc *testContext, t *testing.T) {

	t.Run(GetTestName(tc.params, "Marshaller/Parameters/Binary"), func(t *testing.T) {
		bytes, err := tc.params.MarshalBinary()
		assert.Nil(t, err)
		var p Parameters
		err = p.UnmarshalBinary(bytes)
		assert.Nil(t, err)
		assert.Equal(t, tc.params, p)
		assert.Equal(t, tc.params.RingQ(), p.RingQ())
		assert.Equal(t, tc.params.MarshalBinarySize(), len(bytes))
	})

	t.Run(GetTestName(tc.params, "Marshaller/Parameters/JSON"), func(t *testing.T) {
		// checks that parameters can be marshalled without error
		data, err := json.Marshal(tc.params)
		assert.Nil(t, err)
		assert.NotNil(t, data)

		// checks that ckks.Parameters can be unmarshalled without error
		var paramsRec Parameters
		err = json.Unmarshal(data, &paramsRec)
		assert.Nil(t, err)
		assert.True(t, tc.params.Equals(paramsRec))

		// checks that ckks.Parameters can be unmarshalled with log-moduli definition without error
		dataWithLogModuli := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60], "DefaultScale":1.0}`, tc.params.LogN()))
		var paramsWithLogModuli Parameters
		err = json.Unmarshal(dataWithLogModuli, &paramsWithLogModuli)
		assert.Nil(t, err)
		assert.Equal(t, 2, paramsWithLogModuli.QCount())
		assert.Equal(t, 1, paramsWithLogModuli.PCount())
		assert.Equal(t, ring.Standard, paramsWithLogModuli.RingType())  // Omitting the RingType field should result in a standard instance
		assert.Equal(t, rlwe.DefaultSigma, paramsWithLogModuli.Sigma()) // Omitting sigma should result in Default being used

		// checks that ckks.Parameters can be unmarshalled with log-moduli definition with empty P without error
		dataWithLogModuliNoP := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[],"DefaultScale":1.0,"RingType": "ConjugateInvariant"}`, tc.params.LogN()))
		var paramsWithLogModuliNoP Parameters
		err = json.Unmarshal(dataWithLogModuliNoP, &paramsWithLogModuliNoP)
		assert.Nil(t, err)
		assert.Equal(t, 2, paramsWithLogModuliNoP.QCount())
		assert.Equal(t, 0, paramsWithLogModuliNoP.PCount())
		assert.Equal(t, ring.ConjugateInvariant, paramsWithLogModuliNoP.RingType())

		// checks that one can provide custom parameters for the secret-key and error distributions
		dataWithCustomSecrets := []byte(fmt.Sprintf(`{"LogN":%d,"LogQ":[50,50],"LogP":[60],"DefaultScale":1.0,"H": 192, "Sigma": 6.6}`, tc.params.LogN()))
		var paramsWithCustomSecrets Parameters
		err = json.Unmarshal(dataWithCustomSecrets, &paramsWithCustomSecrets)
		assert.Nil(t, err)
		assert.Equal(t, 6.6, paramsWithCustomSecrets.Sigma())
		assert.Equal(t, 192, paramsWithCustomSecrets.HammingWeight())
	})
}
