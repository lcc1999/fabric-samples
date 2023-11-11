package drlwe

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func BenchmarkDRLWE(b *testing.B) {

	// defaultParams := []rlwe.ParametersLiteral{rlwe.TestPN12QP109, rlwe.TestPN13QP218, rlwe.TestPN14QP438, rlwe.TestPN15QP880}
	defaultParams := []rlwe.ParametersLiteral{rlwe.TestPN12QP109, rlwe.TestPN13QP218}
	thresholdInc := 5

	if testing.Short() {
		defaultParams = defaultParams[:2]
		thresholdInc = 5
	}

	if *flagParamString != "" {
		var jsonParams rlwe.ParametersLiteral
		json.Unmarshal([]byte(*flagParamString), &jsonParams)
		defaultParams = []rlwe.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, p := range defaultParams {
		params, err := rlwe.NewParametersFromLiteral(p)
		if err != nil {
			panic(err)
		}

		_=thresholdInc
		benchPublicKeyGen(params, b)
		benchRelinKeyGen(params, b)
		benchKeySwitch(params, b)
		// benchRotKeyGen(params, b)

		// Varying t
		thresholdInc = 1
		// for t := 2; t <= 20; t += thresholdInc {
		// 	benchThreshold(params, t, b)
		// }

	}
}

func benchString(opname string, params rlwe.Parameters) string {
	return fmt.Sprintf("%s/LogN=%d/logQP=%d", opname, params.LogN(), params.LogQP())
}

func benchPublicKeyGen(params rlwe.Parameters, b *testing.B) {

	ckg := NewCKGProtocol(params)
	sk := rlwe.NewKeyGenerator(params).GenSecretKey()
	s1 := ckg.AllocateShare()
	crs, _ := utils.NewPRNG()

	crp := ckg.SampleCRP(crs)

	b.Run(benchString("PublicKeyGen/Round1/Gen", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			ckg.GenShare(sk, crp, s1)
		}
	})

	b.Run(benchString("PublicKeyGen/Round1/Agg", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			ckg.AggregateShares(s1, s1, s1)
		}
	})

	pk := rlwe.NewPublicKey(params)
	b.Run(benchString("PublicKeyGen/Finalize", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ckg.GenPublicKey(s1, crp, pk)
		}
	})
}

func benchRelinKeyGen(params rlwe.Parameters, b *testing.B) {

	rkg := NewRKGProtocol(params)
	sk := rlwe.NewKeyGenerator(params).GenSecretKey()
	ephSk, share1, share2 := rkg.AllocateShare()
	rlk := rlwe.NewRelinearizationKey(params, 2)
	crs, _ := utils.NewPRNG()
	pk := rlwe.NewPublicKey(params)

	crp := rkg.SampleCRP(crs)

	b.Run(benchString("RelinKeyGen/GenRound1", params), func(b *testing.B) {
		// tttt,_:= share2.MarshalBinary()
		// b.Logf("\n\nid: %v\n\n", len(tttt))
		for i := 0; i < b.N; i++ {
			rkg.GenShareRoundOne(sk, crp, ephSk, share1)
		}
	})

	b.Run(benchString("RelinKeyGen/GenRound2", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.GenShareRoundTwo(ephSk, sk, share1, share2)
		}
	})

	b.Run(benchString("RelinKeyGen/GenShare", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.GenShare(sk, pk, share1)
		}
	})

	b.Run(benchString("RelinKeyGen/Agg", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.AggregateShares(share1, share1, share1)
		}
	})

	b.Run(benchString("RelinKeyGen/Finalize", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.GenRelinearizationKey(share1, share2, rlk)
		}
	})
	b.Run(benchString("RelinKeyGen/GenRelinearizationKeyOneRound", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rkg.GenRelinearizationKeyOneRound(share1, rlk)
		}
	})
}

func benchKeySwitch(params rlwe.Parameters, b *testing.B) {

	sigmaSmudging := 8 * rlwe.DefaultSigma
	pcks := NewPCKSProtocol(params, sigmaSmudging)
	prng, _ := utils.NewPRNG()
	ciphertext := rlwe.NewCiphertextRandom(prng, params, 1, params.MaxLevel())
	result := rlwe.NewCiphertext(params, 1, ciphertext.Level())
	share := pcks.AllocateShare(ciphertext.Level())
	aggregate := pcks.AllocateShare(ciphertext.Level())
	sk := rlwe.NewKeyGenerator(params).GenSecretKey()
	pk := rlwe.NewKeyGenerator(params).GenPublicKey(sk)

	b.Run(benchString("KeySwitch/Round1/Gen", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			pcks.GenShare(sk, pk, ciphertext, share)
		}
	})

	b.Run(benchString("KeySwitch/Round1/Agg", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			pcks.AggregateShares(aggregate, share, aggregate)
		}
	})

	b.Run(benchString("KeySwitch/Finalize", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pcks.KeySwitch(ciphertext, aggregate, result)
		}
	})
}

func benchRotKeyGen(params rlwe.Parameters, b *testing.B) {

	rtg := NewRTGProtocol(params)
	sk := rlwe.NewKeyGenerator(params).GenSecretKey()
	share := rtg.AllocateShare()
	crs, _ := utils.NewPRNG()
	crp := rtg.SampleCRP(crs)

	b.Run(benchString("RotKeyGen/Round1/Gen", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			rtg.GenShare(sk, params.GaloisElementForRowRotation(), crp, share)
		}
	})

	b.Run(benchString("RotKeyGen/Round1/Agg", params), func(b *testing.B) {

		for i := 0; i < b.N; i++ {
			rtg.AggregateShares(share, share, share)
		}
	})

	rotKey := rlwe.NewSwitchingKey(params, params.MaxLevelQ(), params.MaxLevelP())
	b.Run(benchString("RotKeyGen/Finalize", params), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rtg.GenRotationKey(share, crp, rotKey)
		}
	})
}

func benchThreshold(params rlwe.Parameters, t int, b *testing.B) {

	type Party struct {
		*Thresholdizer
		*Combiner
		gen *ShamirPolynomial
		s   *rlwe.SecretKey
		sk  *rlwe.SecretKey
		tsk *ShamirSecretShare
	}

	shamirPks := make([]ShamirPublicPoint, t)
	for i := range shamirPks {
		shamirPks[i] = ShamirPublicPoint(i + 1)
	}

	p := new(Party)
	p.s = rlwe.NewSecretKey(params)
	p.Thresholdizer = NewThresholdizer(params)
	p.tsk = p.Thresholdizer.AllocateThresholdSecretShare()
	p.sk = rlwe.NewSecretKey(params)

	b.Run(benchString("Thresholdizer/GenShamirPolynomial", params)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.gen, _ = p.Thresholdizer.GenShamirPolynomial(t, p.s)
		}
	})

	shamirShare := p.Thresholdizer.AllocateThresholdSecretShare()

	b.Run(benchString("Thresholdizer/GenShamirSecretShare", params)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		// tttt,_:= shamirShare.MarshalBinary()
		// b.Logf("\n\nid: %v\n\n", len(tttt))
		for i := 0; i < b.N; i++ {
			p.Thresholdizer.GenShamirSecretShare(shamirPks[0], p.gen, shamirShare)
		}
	})

	b.Run(benchString("Thresholdizer/AggregateShares", params)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Thresholdizer.AggregateShares(shamirShare, shamirShare, shamirShare)
		}
	})

	p.Combiner = NewCombiner(params, shamirPks[0], shamirPks, t)

	b.Run(benchString("Combiner/GenAdditiveShare", params)+fmt.Sprintf("/threshold=%d", t), func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			p.Combiner.GenAdditiveShare(shamirPks, shamirPks[0], p.tsk, p.sk)
		}
	})
}