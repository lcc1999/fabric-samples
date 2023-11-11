/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"time"
	"bytes"
	"encoding/json"
	"math/big"
	"errors"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/dckks"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
)

type Party struct {
	sk *rlwe.SecretKey
	//the public key of the result decrypter
	pk *rlwe.PublicKey

	pk_share *drlwe.CKGShare
	cpk *rlwe.PublicKey

	rlk_secret *rlwe.SecretKey
	rlk_share1 *drlwe.RKGShare
	rlk_share2 *drlwe.RKGShare

	sw_share *drlwe.PCKSShare
}

type PartyPub struct {
	spk_share []byte
	srlk_share1 []byte
	srlk_share2 []byte
	ssw_share []byte
}
type Computer struct {
	sk *rlwe.SecretKey
	pk *rlwe.PublicKey
	spk []byte
	crp_pk drlwe.CKGCRP
	scrp_pk []byte
	crp_rlk drlwe.RKGCRP
	scrp_rlk []byte

	parties []PartyPub

	scpk []byte

	rlk_aggregate1 *drlwe.RKGShare
	srlk_aggregate1 []byte
	rlk_aggregate2 *drlwe.RKGShare
	rlk *rlwe.RelinearizationKey

	result *rlwe.Ciphertext
	sresult []byte

	sw_result *rlwe.Ciphertext
	ssw_result []byte
}

const (
	N = 2
	seed = "test"
	literal = "PN12QP109CI"//"PN12QP109", "PN12QP109CI", "PN13QP218", "PN13QP218CI"
	sigmaSmudging = 8 * rlwe.DefaultSigma
)

var now = time.Now()
var assetId = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

var params ckks.Parameters
var kgen rlwe.KeyGenerator
var encoder ckks.Encoder
var crs drlwe.CRS
var ckg *drlwe.CKGProtocol
var rkg *drlwe.RKGProtocol
var pcks *drlwe.PCKSProtocol
var parties = make([]Party, N)
var computer Computer

var ciphertext *rlwe.Ciphertext

func main() {
	params, _ = ParametersFromString(literal)
	kgen = ckks.NewKeyGenerator(params)
	computer.sk, computer.pk = kgen.GenKeyPair()
	computer.parties = make([]PartyPub, N)
	encoder = ckks.NewEncoder(params)
	crs, _ = utils.NewKeyedPRNG([]byte(seed))

	initLedger()
	cpkGen()
	//rlkGen1()
	//rlkGen2()
	rlkGen()
	encryptAndEval()
	keySwitch()
	downloadAndDecrypt()


	literal := "PN12QP109CI"
	method := "MulRelinNew"
	start := time.Now()
	delta := time.Since(start).String()
	params, _ = ParametersFromString(literal)
	rlk := rlwe.NewRelinearizationKey(params.Parameters, 1)
	data := ckks.NewCiphertext(params, 1, params.MaxLevel())
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	switch method{
	case "MulRelinNew":
		start = time.Now()
		_ = evaluator.MulRelinNew(data, data)
		delta = time.Since(start).String()
		fmt.Println(delta)
	}
}

// This type of transaction would typically only be run once by an application the first time it was started after its
// initial deployment. A new version of the chaincode deployed later would likely not need to run an "init" function.
func initLedger() {
	fmt.Printf("\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger \n")

	ckg = dckks.NewCKGProtocol(params)
	computer.crp_pk = ckg.SampleCRP(crs)
	rkg = dckks.NewRKGProtocol(params)
	computer.crp_rlk = rkg.SampleCRP(crs)

	computer.spk, _ = computer.pk.MarshalBinary()
	computer.scrp_pk, _ =  CKGCRPMarshalBinary(computer.crp_pk)
	computer.scrp_rlk, _ = RKGCRPMarshalBinary(computer.crp_rlk)

	fmt.Println(len(computer.spk),len(computer.scrp_pk),len(computer.scrp_rlk))
}

func cpkGen() {
	fmt.Printf("\n--> Submit Transaction: CpkGen, function returns the result\n")

	//Party
	start := time.Now()
	for i := 0; i < N; i++ {
		parties[i].sk = kgen.GenSecretKey()
		parties[i].pk_share = ckg.AllocateShare()
		parties[i].cpk = rlwe.NewPublicKey(params.Parameters)
		crp_pk, _ := CKGCRPUnmarshalBinary(computer.scrp_pk)
		ckg.GenShare(parties[i].sk, crp_pk, parties[i].pk_share)
		computer.parties[i].spk_share, _ = parties[i].pk_share.MarshalBinary()
	}
	t := time.Since(start)
	fmt.Printf("time %s\n",t)

	//Computer
	pk_aggregate := ckg.AllocateShare()
	for i := 0; i < N; i++ {
		pk_share := new(drlwe.CKGShare)
		_ = pk_share.UnmarshalBinary(computer.parties[i].spk_share)
		ckg.AggregateShares(pk_aggregate, pk_share, pk_aggregate)
	}
	cpk := rlwe.NewPublicKey(params.Parameters)
	ckg.GenPublicKey(pk_aggregate, computer.crp_pk, cpk)
	computer.scpk, _ = cpk.MarshalBinary()

	//Party
	start = time.Now()
	for i := 0; i < N; i++ {
		_ = parties[i].cpk.UnmarshalBinary(computer.scpk)
		parties[i].pk = new(rlwe.PublicKey)
		_ = parties[i].pk.UnmarshalBinary(computer.spk)
	}
	t = time.Since(start)
	fmt.Printf("time %s\n",t)
}

func rlkGen1() {
	fmt.Printf("\n--> Submit Transaction: RlkGen1, function returns the result\n")

	//Party
	start := time.Now()
	for i := 0; i < N; i++ {
		parties[i].rlk_secret, parties[i].rlk_share1, parties[i].rlk_share2 = rkg.AllocateShare()
		crp_rlk, _ := RKGCRPUnmarshalBinary(computer.scrp_rlk)
		rkg.GenShareRoundOne(parties[i].sk, crp_rlk, parties[i].rlk_secret, parties[i].rlk_share1)
		computer.parties[i].srlk_share1, _ = parties[i].rlk_share1.MarshalBinary()
	}
	t := time.Since(start)
	fmt.Printf("time %s\n",t)

	//Computer
	_, computer.rlk_aggregate1, computer.rlk_aggregate2 = rkg.AllocateShare()
	for i := 0; i < N; i++ {
		rlk_share1 := new(drlwe.RKGShare)
		_ = rlk_share1.UnmarshalBinary(computer.parties[i].srlk_share1)
		rkg.AggregateShares(computer.rlk_aggregate1, rlk_share1, computer.rlk_aggregate1)
	}
	computer.srlk_aggregate1, _ = computer.rlk_aggregate1.MarshalBinary()
	//Party download srlk_aggregate1
}

func rlkGen2() {
	fmt.Printf("\n--> Submit Transaction: RlkGen2, function returns the result\n")

	//Party
	start := time.Now()
	for i := 0; i < N; i++ {
		computer.rlk_aggregate1 = new(drlwe.RKGShare)
		_ = computer.rlk_aggregate1.UnmarshalBinary(computer.srlk_aggregate1)
		rkg.GenShareRoundTwo(parties[i].rlk_secret, parties[i].sk, computer.rlk_aggregate1, parties[i].rlk_share2)
		computer.parties[i].srlk_share2, _ = parties[i].rlk_share2.MarshalBinary()
	}
	t := time.Since(start)
	fmt.Printf("time %s\n",t)

	//Computer
	for i := 0; i < N; i++ {
		rlk_share2 := new(drlwe.RKGShare)
		_ = rlk_share2.UnmarshalBinary(computer.parties[i].srlk_share2)
		rkg.AggregateShares(computer.rlk_aggregate2, rlk_share2, computer.rlk_aggregate2)
	}

	computer.rlk = rlwe.NewRelinearizationKey(params.Parameters, 2)
	rkg.GenRelinearizationKey(computer.rlk_aggregate1, computer.rlk_aggregate2, computer.rlk)
	
	//Party return success
}

func rlkGen() {
	fmt.Printf("\n--> Submit Transaction: RlkGen, function returns the result\n")

	//Party
	start := time.Now()
	for i := 0; i < N; i++ {
		parties[i].rlk_secret, parties[i].rlk_share1, parties[i].rlk_share2 = rkg.AllocateShare()
		start := time.Now()
		rkg.GenShare(parties[i].sk, parties[i].cpk, parties[i].rlk_share1)
		fmt.Println(time.Since(start))
		computer.parties[i].srlk_share1, _ = parties[i].rlk_share1.MarshalBinary()
	}
	t := time.Since(start)
	fmt.Printf("time %s\n",t)

	//Computer
	_, computer.rlk_aggregate1, computer.rlk_aggregate2 = rkg.AllocateShare()
	for i := 0; i < N; i++ {
		rlk_share1 := new(drlwe.RKGShare)
		_ = rlk_share1.UnmarshalBinary(computer.parties[i].srlk_share1)
		rkg.AggregateShares(computer.rlk_aggregate1, rlk_share1, computer.rlk_aggregate1)
	}

	computer.rlk = rlwe.NewRelinearizationKey(params.Parameters, 1)
	rkg.GenRelinearizationKeyOneRound(computer.rlk_aggregate1, computer.rlk)
	//Party download srlk_aggregate1
}

func encryptAndEval() {
	fmt.Printf("\n--> Submit Transaction: EncryptAndEval, function returns the result\n")

	//Party
	encryptor := ckks.NewEncryptor(params, parties[0].cpk)
	values := make([]float64, params.Slots())
	for i := 0; i < params.Slots(); i++{
		values[i] = 3.0
	}
	plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	ciphertext = encryptor.EncryptNew(plaintext)

	sciphertext, _ := ciphertext.MarshalBinary()

	//Computer
	ct := new(rlwe.Ciphertext)
	_ = ct.UnmarshalBinary(sciphertext)
	
	// computer.rlk = rlwe.NewRelinearizationKey(params.Parameters, 2)
	// _ = computer.rlk.UnmarshalBinary(computer.srlk)

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: computer.rlk})
	computer.result = evaluator.MulRelinNew(ct, ct)
	computer.sresult, _ = computer.result.MarshalBinary()



	Q := params.QLvl(params.MaxLevel())
	r := new(big.Int)
	r.Div(Q, big.NewInt(2))
	rr := new(big.Float)
    rr.SetInt(Q)
	rr.Quo(rr, big.NewFloat(2))
	D := params.DefaultScale().Value

	r_D := new(big.Float)
	r_D.Copy(rr)
	r_D.Quo(r_D, &D)
	rf,_ := r_D.Float64()
	fmt.Println("Q",Q)
	fmt.Println("r",r)
	fmt.Println("rr",rr)
	fmt.Println("D",&D)
	fmt.Println("r_D",r_D)
	fmt.Println("rf",rf)
	encryptor = ckks.NewEncryptor(params, computer.pk)
	fmt.Println(params.Slots())
	values = make([]float64, params.Slots())
	for i := 0; i < params.Slots(); i++{
		values[i] = float64(rf)
	}

	values1 := make([]float64, params.Slots())
	start := time.Now()
	for i := 0; i < params.Slots(); i++{
		x := new(big.Float)
		x.SetFloat64(float64(i))
		x.Mul(x,&D)

		// fmt.Println(x,Q)
		QQ := new(big.Int)
		QQ.Add(Q,big.NewInt(0))
		xx,_ := x.Int(QQ)
		// fmt.Println(xx,Q)
		xx.Sub(xx,r)
		xx.Mod(xx,Q)
		// fmt.Println(xx)
		
		xxx := new(big.Float)
		xxx.SetInt(xx)
		// fmt.Println(xxx)
		xxx.Quo(xxx,&D)
		// fmt.Println(xxx)
		xxxx,_:=xxx.Float64()
		_=xxxx
		values1[i] = float64(xxxx)
	}
	delta := time.Since(start)
	fmt.Println(delta)
	fmt.Println(delta/4096)

	start = time.Now()
	plaintext = encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	ciphertext = encryptor.EncryptNew(plaintext)
	delta = time.Since(start)
	fmt.Println(delta)

	evaluator = ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: nil})
	plaintext = encoder.EncodeNew(values1, params.MaxLevel(), params.DefaultScale(), params.LogSlots())

	start = time.Now()
	evaluator.Add(ciphertext,plaintext,ciphertext)
	delta = time.Since(start)
	fmt.Println(delta)
	
	decryptor := ckks.NewDecryptor(params, computer.sk)
	plaintext = decryptor.DecryptNew(ciphertext)
	value := encoder.Decode(plaintext, params.LogSlots())

	min,max:=min_max(value)
	fmt.Printf("min:%f,max:%f,mean:%f\n",min,max,mean(value))
}

func keySwitch() {
	fmt.Printf("\n--> Submit Transaction: keySwitch, function returns the result\n")

	//Party
	start := time.Now()
	pcks = dckks.NewPCKSProtocol(params, sigmaSmudging)
	for i := 0; i < N; i++ {
		result := new(rlwe.Ciphertext)

		_ = result.UnmarshalBinary(computer.sresult)

		parties[i].sw_share = pcks.AllocateShare(result.Level())
		pcks.GenShare(parties[i].sk, parties[i].pk, result, parties[i].sw_share)
		computer.parties[i].ssw_share, _ = parties[i].sw_share.MarshalBinary()
	}
	t := time.Since(start)
	fmt.Printf("time %s\n",t)

	//Computer
	computer.result = new(rlwe.Ciphertext)
	_ = computer.result.UnmarshalBinary(computer.sresult)

	sw_aggregate := pcks.AllocateShare(computer.result.Level())
	for i := 0; i < N; i++ {
		sw_share := new(drlwe.PCKSShare)
		_ = sw_share.UnmarshalBinary(computer.parties[i].ssw_share)
		pcks.AggregateShares(sw_aggregate, sw_share, sw_aggregate)
	}
	computer.sw_result = ckks.NewCiphertext(params, 1, computer.result.Level())
	pcks.KeySwitch(computer.result, sw_aggregate, computer.sw_result)
	computer.ssw_result, _ = computer.sw_result.MarshalBinary()
}

func downloadAndDecrypt() {
	fmt.Printf("\n--> Evaluate Transaction: GetData, function returns the result\n")

	//Computer
	decryptor := ckks.NewDecryptor(params, computer.sk)
	sw_result := new(rlwe.Ciphertext)

	_ = sw_result.UnmarshalBinary(computer.ssw_result)

	plaintext := decryptor.DecryptNew(sw_result)
	value := encoder.Decode(plaintext, params.LogSlots())
	min,max:=min_max(value)
	fmt.Printf("min:%f,max:%f,mean:%f\n",min,max,mean(value))



	encryptor := ckks.NewEncryptor(params, computer.pk)
	ppp:=rlwe.NewCiphertextQP(params.Parameters, params.MaxLevelQ(), params.MaxLevelP())
	fmt.Println(ppp.IsNTT,ppp.IsMontgomery)
	encryptor.EncryptZero(&ppp)
	fmt.Println(ppp.IsNTT,ppp.IsMontgomery)

	ct := ckks.NewCiphertext(params, 1, params.MaxLevel())
	fmt.Println(ct.IsNTT,ct.IsMontgomery)
	var basisextender *ring.BasisExtender
	if params.PCount() != 0 {
		basisextender = ring.NewBasisExtender(params.RingQ(), params.RingP())
	}
	levelQ := ct.Level()
	levelP := 0
	ringQP := params.RingQP().AtLevel(levelQ, levelP)
	// ringQP.INTT(computer.pk.Value[0], computer.pk.Value[0])
	// ringQP.INTT(computer.pk.Value[1], computer.pk.Value[1])
	// basisextender.ModDownQPtoQ(levelQ, levelP, computer.pk.Value[0].Q, computer.pk.Value[0].P, ct.Value[0])
	// basisextender.ModDownQPtoQ(levelQ, levelP, computer.pk.Value[1].Q, computer.pk.Value[1].P, ct.Value[1])
	ringQP.INTT(ppp.Value[0], ppp.Value[0])
	ringQP.INTT(ppp.Value[1], ppp.Value[1])
	basisextender.ModDownQPtoQ(levelQ, levelP, ppp.Value[0].Q, ppp.Value[0].P, ct.Value[0])
	basisextender.ModDownQPtoQ(levelQ, levelP, ppp.Value[1].Q, ppp.Value[1].P, ct.Value[1])
	if ct.IsNTT {
		ringQP.RingQ.NTT(ct.Value[0], ct.Value[0])
		ringQP.RingQ.NTT(ct.Value[1], ct.Value[1])
	}
	fmt.Println(computer.rlk.Keys[0].Value[0][0].IsNTT,computer.rlk.Keys[0].Value[0][0].IsMontgomery)
	fmt.Println(parties[0].cpk.IsNTT,parties[0].cpk.IsMontgomery)
	plaintext = decryptor.DecryptNew(ct)
	value = encoder.Decode(plaintext, params.LogSlots())
	min,max=min_max(value)
	fmt.Printf("min:%f,max:%f,mean:%f\n",min,max,mean(value))
}

// Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}




func ParametersFromString(param string) (ckks.Parameters, error) {
	var params ckks.Parameters
	var err error
	switch param {
	case "PN12QP109":
		params, err = ckks.NewParametersFromLiteral(ckks.PN12QP109)
	case "PN13QP218":
		params, err = ckks.NewParametersFromLiteral(ckks.PN13QP218)
	case "PN14QP438":
		params, err = ckks.NewParametersFromLiteral(ckks.PN14QP438)
	case "PN15QP880":
		params, err = ckks.NewParametersFromLiteral(ckks.PN15QP880)
	case "PN16QP1761":
		params, err = ckks.NewParametersFromLiteral(ckks.PN16QP1761)
	case "PN12QP109CI":
		params, err = ckks.NewParametersFromLiteral(ckks.PN12QP109CI)
	case "PN13QP218CI":
		params, err = ckks.NewParametersFromLiteral(ckks.PN13QP218CI)
	case "PN14QP438CI":
		params, err = ckks.NewParametersFromLiteral(ckks.PN14QP438CI)
	case "PN15QP880CI":
		params, err = ckks.NewParametersFromLiteral(ckks.PN15QP880CI)
	case "PN16QP1761CI":
		params, err = ckks.NewParametersFromLiteral(ckks.PN16QP1761CI)
	case "PN12QP101pq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN12QP101pq)
	case "PN13QP202pq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN13QP202pq)
	case "PN14QP411pq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN14QP411pq)
	case "PN15QP827pq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN15QP827pq)
	case "PN16QP1654pq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN16QP1654pq)
	case "PN12QP101CIpq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN12QP101CIpq)
	case "PN13QP202CIpq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN13QP202CIpq)
	case "PN14QP411CIpq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN14QP411CIpq)
	case "PN15QP827CIpq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN15QP827CIpq)
	case "PN16QP1654CIpq":
		params, err = ckks.NewParametersFromLiteral(ckks.PN16QP1654CIpq)	
	default:
		params, err = ckks.NewParametersFromLiteral(ckks.PN12QP109)
	}
	return params,err
}
//generate SecretKey,PublicKey,RelinearizationKey and RotationKey
func Keygen(params ckks.Parameters, rotations []int) (*rlwe.SecretKey, *rlwe.PublicKey, []byte, []byte, error) {
	
	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()
	rlk := kgen.GenRelinearizationKey(sk, 2)
	rotkey := kgen.GenRotationKeysForRotations(rotations, params.RingType() == ring.Standard, sk)
	srlk, err := rlk.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	srotkey, err := rotkey.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return sk, pk, srlk, srotkey, nil
}

//encrypt data with PublicKey
func Encrypt(params ckks.Parameters, pk *rlwe.PublicKey, data float64) ([]byte, error){

	encoder := ckks.NewEncoder(params)
	encryptor := ckks.NewEncryptor(params, pk)

	values := make([]float64, params.Slots())
	for i := 0; i < params.Slots(); i++{
		values[i] = data
	}

	plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	var ciphertext *rlwe.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)

	cipher, err := ciphertext.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

//decrypt ciphertext with SecretKey
func Decrypt(params ckks.Parameters, sk *rlwe.SecretKey, cipher []byte, k int) (float64, error){

	var ciphertext rlwe.Ciphertext
	err := ciphertext.UnmarshalBinary(cipher)
	if err != nil {
		return 0, err
	}

	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	value := encoder.Decode(decryptor.DecryptNew(&ciphertext), params.LogSlots())
	min,max:=min_max(value)
	fmt.Printf("min:%f,max:%f,mean:%f\n",min,max,mean(value))
	if k>=0 && k<len(value) {
		return real(value[k]), nil
	}else {
		return mean(value), nil
	}
}

func CKGCRPMarshalBinary(crp_pk drlwe.CKGCRP) ([]byte, error) {
	data, err := (*ringqp.Poly)(&crp_pk).MarshalBinary()
	return data, err
}

func CKGCRPUnmarshalBinary(data []byte) (crp_pk drlwe.CKGCRP, err error) {
	poly := new(ringqp.Poly)
	err = poly.UnmarshalBinary(data)
	crp_pk = drlwe.CKGCRP(*poly)
	return crp_pk, nil
}

func RKGCRPMarshalBinary(crp_rlk drlwe.RKGCRP) ([]byte, error) {
	data := make([]byte, 2+crp_rlk[0][0].MarshalBinarySize64()*len(crp_rlk)*len(crp_rlk[0]))
	if len(crp_rlk) > 0xFF {
		return []byte{}, errors.New("RKGCRP : uint8 overflow on length")
	}

	if len(crp_rlk[0]) > 0xFF {
		return []byte{}, errors.New("RKGCRP : uint8 overflow on length")
	}

	data[0] = uint8(len(crp_rlk))
	data[1] = uint8(len(crp_rlk[0]))

	ptr := 2
	var inc int
	var err error
	for i := range crp_rlk {
		for _, el := range crp_rlk[i] {

			if inc, err = el.Encode64(data[ptr:]); err != nil {
				return []byte{}, err
			}
			ptr += inc
		}
	}

	return data, nil
}

func RKGCRPUnmarshalBinary(data []byte) (crp_rlk drlwe.RKGCRP, err error) {
	crp_rlk = make([][]ringqp.Poly, data[0])
	ptr := 2
	var inc int
	for i := range crp_rlk {
		crp_rlk[i] = make([]ringqp.Poly, data[1])
		for j := range crp_rlk[i] {

			if inc, err = crp_rlk[i][j].Decode64(data[ptr:]); err != nil {
				return nil, err
			}
			ptr += inc

		}
	}

	return crp_rlk, nil
}

func mean(v []complex128) float64 {
    var res float64 = 0
    var n int = len(v)
    for i := 0; i < n; i++ {
        res += real(v[i])
    }
    return res / float64(n)
}
func min(x, y int) int {
    if x < y {
        return x
    }
    return y
}
func min_max(v []complex128) (float64,float64) {
    var min float64 = real(v[0])
	var max float64 = real(v[0])
    var n int = len(v)
    for i := 0; i < n; i++ {
        if real(v[i]) < min {
			min = real(v[i])
		}
		if real(v[i]) > max {
			max = real(v[i])
		}
    }
	return min,max
}
