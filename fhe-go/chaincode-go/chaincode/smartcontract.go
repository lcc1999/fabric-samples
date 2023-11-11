package chaincode

import (
	"fmt"
	"strconv"
	"encoding/binary"
	"math"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/dckks"
	"github.com/tuneinsight/lattigo/v4/rlwe/ringqp"
	"github.com/tuneinsight/lattigo/v4/utils"
)

const sigmaSmudging = 8 * rlwe.DefaultSigma

const (
    START      byte = 0
    FINISH_CPK      byte = 1
    FINISH_RLK      byte = 2
	FINISH_CPK_RLK      byte = 3
    FINISH_CPK_DATA      byte = 4
	FINISH_CPK_RLK_DATA      byte = 5
	FINISH_EVAL byte = 6
	FINISH_SWITCH byte = 7
)

type CPK_AGG struct {
	set map[string]bool
	cpk_agg []byte
}

type RLK_AGG struct {
	set map[string]bool
	rlk_agg []byte
}

type SW_AGG struct {
	set map[string]bool
	sw_agg []byte
}

// SmartContract provides functions for managing an Asset
type SmartContract struct {
	contractapi.Contract
	N int
	params ckks.Parameters
	ckg *drlwe.CKGProtocol
	rkg *drlwe.RKGProtocol
	pcks *drlwe.PCKSProtocol
	idP map[string]int
	// map[string]int idQ = map[string]int{"eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMS5leGFtcGxlLmNvbSxPPW9yZzEuZXhhbXBsZS5jb20sTD1EdXJoYW0sU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUw==":0, "eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMi5leGFtcGxlLmNvbSxPPW9yZzIuZXhhbXBsZS5jb20sTD1IdXJzbGV5LFNUPUhhbXBzaGlyZSxDPVVL":1}
	idK map[string]int
	MS map[byte]map[string]byte

	mask []byte
	evaluator []ckks.Evaluator
}



// Asset describes basic details of what makes up a simple asset
// Insert struct field in alphabetic order => to achieve determinism across languages
// golang keeps the order when marshal to json but doesn't order automatically

// InitLedger adds a base set of assets to the ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface, n int, literal, spk, scrp_pk string) error {

	var err error
	s.N = n
	s.params, err = ParametersFromString(literal)
	if err != nil {
		return fmt.Errorf("failed ParametersFromString. %v", err)
	}
	s.idP=map[string]int{"eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMS5leGFtcGxlLmNvbSxPPW9yZzEuZXhhbXBsZS5jb20sTD1EdXJoYW0sU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUw==":0, "eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMi5leGFtcGxlLmNvbSxPPW9yZzIuZXhhbXBsZS5jb20sTD1IdXJzbGV5LFNUPUhhbXBzaGlyZSxDPVVL":1}
	s.idK=map[string]int{"eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMS5leGFtcGxlLmNvbSxPPW9yZzEuZXhhbXBsZS5jb20sTD1EdXJoYW0sU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUw==0":0, "eDUwOTo6Q049dXNlcjEsT1U9Y2xpZW50LE89SHlwZXJsZWRnZXIsU1Q9Tm9ydGggQ2Fyb2xpbmEsQz1VUzo6Q049Y2Eub3JnMi5leGFtcGxlLmNvbSxPPW9yZzIuZXhhbXBsZS5jb20sTD1IdXJzbGV5LFNUPUhhbXBzaGlyZSxDPVVL0":1}

	s.ckg = dckks.NewCKGProtocol(s.params)
	s.rkg = dckks.NewRKGProtocol(s.params)
	s.pcks = dckks.NewPCKSProtocol(s.params, sigmaSmudging)
	err = ctx.GetStub().PutState("state", []byte{0})
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	err = ctx.GetStub().PutState("count", []byte{0})
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	err = ctx.GetStub().PutState("spk", []byte(spk))
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	err = ctx.GetStub().PutState("scrp_pk", []byte(scrp_pk))
	if err != nil {
		return fmt.Errorf("failed to put to world state. %v", err)
	}

	// err = ctx.GetStub().PutState("scrp_rlk", []byte(scrp_rlk))
	// if err != nil {
	// 	return fmt.Errorf("failed to put to world state. %v", err)
	// }

	err = ctx.GetStub().SetEvent("spk", []byte(spk))
	if err != nil {
		return fmt.Errorf("failed to SetEvent. %v", err)
	}

	// err = ctx.GetStub().SetEvent("scrp_pk", []byte(scrp_pk))
	// if err != nil {
	// 	return fmt.Errorf("failed to SetEvent. %v", err)
	// }

	s.MS = make(map[byte]map[string]byte)
	for i:=0;i<8;i++{
		s.MS[byte(i)] = make(map[string]byte)
	}
	s.MS[START]["cpk"]=FINISH_CPK
	s.MS[START]["rlk"]=FINISH_RLK
	s.MS[FINISH_RLK]["cpk"]=FINISH_CPK_RLK
	s.MS[FINISH_CPK]["rlk"]=FINISH_CPK_RLK
	s.MS[FINISH_CPK]["data"]=FINISH_CPK_DATA
	s.MS[FINISH_CPK_RLK]["data"]=FINISH_CPK_RLK_DATA
	s.MS[FINISH_CPK_DATA]["rlk"]=FINISH_CPK_RLK_DATA
	s.MS[FINISH_CPK_RLK_DATA]["eval"]=FINISH_EVAL
	s.MS[FINISH_EVAL]["switch"]=FINISH_SWITCH



	params, err := ParametersFromString("PN12QP109CI")
	mask32768 := make([]byte, params.Slots()*8)
	for i:=0;i<params.Slots();i++{
		bits := math.Float64bits(0.0)
		bytes := mask32768[8*i:8*i+8]
		binary.LittleEndian.PutUint64(bytes, bits)
	}
	err = ctx.GetStub().PutState("mask32768", mask32768)

	mask8 := make([]byte, 8)
	bits := math.Float64bits(0.0)
	binary.LittleEndian.PutUint64(mask8, bits)
	err = ctx.GetStub().PutState("mask8", mask8)
	
	prng, _ := utils.NewPRNG()
	cipher := rlwe.NewCiphertextRandom(prng, params.Parameters, 1, params.MaxLevel())
	s.mask, err = cipher.MarshalBinary()
	err = ctx.GetStub().PutState("nomask", s.mask)
	if err != nil {
		return fmt.Errorf("failed to SetEvent. %v", err)
	}


	s.evaluator = make([]ckks.Evaluator, 2)
	for i,l := range [2]string{"PN12QP109", "PN13QP218"} {
		params, _ = ParametersFromString(literal)
		rlk := rlwe.NewRelinearizationKey(params.Parameters, 1)
		prng, _ = utils.NewPRNG()
		ciphertext1 := rlwe.NewCiphertextRandom(prng, params.Parameters, 1, params.MaxLevel())
		ciphertext2 := rlwe.NewCiphertextRandom(prng, params.Parameters, 1, params.MaxLevel())
		receiver := rlwe.NewCiphertextRandom(prng, params.Parameters, 2, params.MaxLevel())
		sciphertext1, _ := ciphertext1.MarshalBinary()
		_ = ctx.GetStub().PutState("sciphertext1"+l, sciphertext1)
		sciphertext2, _ := ciphertext2.MarshalBinary()
		_ = ctx.GetStub().PutState("sciphertext2"+l, sciphertext2)
		sreceiver, _ := receiver.MarshalBinary()
		_ = ctx.GetStub().PutState("sreceiver"+l, sreceiver)
		s.evaluator[i] = ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk})
	}
	return nil
}

func (s *SmartContract) GetData(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if data == nil {
		return "", fmt.Errorf("the data %s does not exist", key)
	}
	return string(data), nil
}

func (s *SmartContract) SetData(ctx contractapi.TransactionContextInterface, key, data string) (string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "",fmt.Errorf("failed to GetID. %v", err)
	}
	err = ctx.GetStub().PutState(key, []byte(data))
	if err != nil {
		return "",fmt.Errorf("failed to put to world state. %v", err)
	}
	return id, nil
}

func (s *SmartContract) CpkGen(ctx contractapi.TransactionContextInterface, id int, data string) error {
	if id < 0 || id >= s.N {
		return fmt.Errorf("the user %d doesn't exist", id)
	}
	exist, err := ctx.GetStub().GetState("0"+fmt.Sprintf("%d", id))
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("the data %d already exists", id)
	}

	state, err := ctx.GetStub().GetState("state")
	if err != nil {
		return err
	}
	if state[0] != 0 {
		return fmt.Errorf("the state is wrong")
	}

	count, err := ctx.GetStub().GetState("count")
	if err != nil {
		return err
	}
	count[0] += 1
	if int(count[0]) == s.N {
		pk_aggregate := s.ckg.AllocateShare()
		for i := 0; i < s.N; i++ {
			var spk_share []byte
			if i != id {
				spk_share, err = ctx.GetStub().GetState("0"+fmt.Sprintf("%d", i))
				if err != nil {
					return err
				}
			}else {
				spk_share = []byte(data)
			}
			pk_share := new(drlwe.CKGShare)
			err = pk_share.UnmarshalBinary(spk_share)
			if err != nil {
				return err
			}
			s.ckg.AggregateShares(pk_aggregate, pk_share, pk_aggregate)
		}
		cpk := rlwe.NewPublicKey(s.params.Parameters)

		scrp_pk, err := ctx.GetStub().GetState("scrp_pk")
		if err != nil {
			return err
		}
		crp_pk, err := CKGCRPUnmarshalBinary(scrp_pk)
		if err != nil {
			return err
		}

		s.ckg.GenPublicKey(pk_aggregate, crp_pk, cpk)
		scpk, err := cpk.MarshalBinary()
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("scpk", scpk)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().PutState("state", []byte{state[0]+1})
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		
		err = ctx.GetStub().SetEvent("scpk", scpk)
		if err != nil {
			return fmt.Errorf("failed to SetEvent. %v", err)
		}
		return ctx.GetStub().PutState("count", []byte{0})
	}else{
		err = ctx.GetStub().PutState("0"+fmt.Sprintf("%d", id), []byte(data))
		if err != nil {
			return err
		}
		return ctx.GetStub().PutState("count", []byte{count[0]})
	}
}

func (s *SmartContract) RlkGen1(ctx contractapi.TransactionContextInterface, id int, data string) error {
	if id < 0 || id >= s.N {
		return fmt.Errorf("the user %d doesn't exist", id)
	}
	exist, err := ctx.GetStub().GetState("1"+fmt.Sprintf("%d", id))
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("the data %d already exists", id)
	}

	state, err := ctx.GetStub().GetState("state")
	if err != nil {
		return err
	}
	if state[0] != 1 {
		return fmt.Errorf("the state is wrong")
	}

	count, err := ctx.GetStub().GetState("count")
	if err != nil {
		return err
	}
	count[0] += 1
	if int(count[0]) == s.N {
		_, rlk_aggregate1, _ := s.rkg.AllocateShare()
		for i := 0; i < s.N; i++ {
			var srlk_share1 []byte
			if i != id {
				srlk_share1, err = ctx.GetStub().GetState("1"+fmt.Sprintf("%d", i))
				if err != nil {
					return err
				}
			}else {
				srlk_share1 = []byte(data)
			}
			rlk_share1 := new(drlwe.RKGShare)
			err = rlk_share1.UnmarshalBinary(srlk_share1)
			if err != nil {
				return err
			}
			s.rkg.AggregateShares(rlk_aggregate1, rlk_share1, rlk_aggregate1)
		}
		
		srlk_aggregate1, err := rlk_aggregate1.MarshalBinary()
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("srlk_aggregate1", srlk_aggregate1)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().PutState("state", []byte{state[0] + 1})
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().SetEvent("srlk_aggregate1", srlk_aggregate1)
		if err != nil {
			return fmt.Errorf("failed to SetEvent. %v", err)
		}
		return ctx.GetStub().PutState("count", []byte{0})
	}else{
		err = ctx.GetStub().PutState("1"+fmt.Sprintf("%d", id), []byte(data))
		if err != nil {
			return err
		}
		return ctx.GetStub().PutState("count", []byte{count[0]})
	}
}

func (s *SmartContract) RlkGen2(ctx contractapi.TransactionContextInterface, id int, data string) error {
	if id < 0 || id >= s.N {
		return fmt.Errorf("the user %d doesn't exist", id)
	}
	exist, err := ctx.GetStub().GetState("2"+fmt.Sprintf("%d", id))
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("the data %d already exists", id)
	}

	state, err := ctx.GetStub().GetState("state")
	if err != nil {
		return err
	}
	if state[0] != 2 {
		return fmt.Errorf("the state is wrong")
	}

	count, err := ctx.GetStub().GetState("count")
	if err != nil {
		return err
	}
	count[0] += 1
	if int(count[0]) == s.N {
		_, _, rlk_aggregate2 := s.rkg.AllocateShare()
		for i := 0; i < s.N; i++ {
			var srlk_share2 []byte
			if i != id {
				srlk_share2, err = ctx.GetStub().GetState("2"+fmt.Sprintf("%d", i))
				if err != nil {
					return err
				}
			}else {
				srlk_share2 = []byte(data)
			}
			rlk_share2 := new(drlwe.RKGShare)
			err = rlk_share2.UnmarshalBinary(srlk_share2)
			if err != nil {
				return err
			}
			s.rkg.AggregateShares(rlk_aggregate2, rlk_share2, rlk_aggregate2)
		}

		srlk_aggregate1, err := ctx.GetStub().GetState("srlk_aggregate1")
		if err != nil {
			return err
		}
		rlk_aggregate1 := new(drlwe.RKGShare)
		err = rlk_aggregate1.UnmarshalBinary(srlk_aggregate1)
		if err != nil {
			return err
		}

		rlk := rlwe.NewRelinearizationKey(s.params.Parameters, 2)
		s.rkg.GenRelinearizationKey(rlk_aggregate1, rlk_aggregate2, rlk)

		srlk, err := rlk.MarshalBinary()
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("srlk", srlk)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().PutState("state", []byte{state[0] + 1})
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		
		err = ctx.GetStub().SetEvent("srlk", []byte("srlk"))
		if err != nil {
			return fmt.Errorf("failed to SetEvent. %v", err)
		}
		return ctx.GetStub().PutState("count", []byte{0})
	}else{
		err = ctx.GetStub().PutState("2"+fmt.Sprintf("%d", id), []byte(data))
		if err != nil {
			return err
		}
		return ctx.GetStub().PutState("count", []byte{count[0]})
	}
}

func (s *SmartContract) RlkGen(ctx contractapi.TransactionContextInterface, id int, data string) error {
	if id < 0 || id >= s.N {
		return fmt.Errorf("the user %d doesn't exist", id)
	}
	exist, err := ctx.GetStub().GetState("1"+fmt.Sprintf("%d", id))
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("the data %d already exists", id)
	}

	state, err := ctx.GetStub().GetState("state")
	if err != nil {
		return err
	}
	if state[0] != 1 {
		return fmt.Errorf("the state is wrong")
	}

	count, err := ctx.GetStub().GetState("count")
	if err != nil {
		return err
	}
	count[0] += 1
	if int(count[0]) == s.N {
		_, _, rlk_aggregate2 := s.rkg.AllocateShare()
		for i := 0; i < s.N; i++ {
			var srlk_share2 []byte
			if i != id {
				srlk_share2, err = ctx.GetStub().GetState("1"+fmt.Sprintf("%d", i))
				if err != nil {
					return err
				}
			}else {
				srlk_share2 = []byte(data)
			}
			rlk_share2 := new(drlwe.RKGShare)
			err = rlk_share2.UnmarshalBinary(srlk_share2)
			if err != nil {
				return err
			}
			s.rkg.AggregateShares(rlk_aggregate2, rlk_share2, rlk_aggregate2)
		}

		rlk := rlwe.NewRelinearizationKey(s.params.Parameters, 1)
		s.rkg.GenRelinearizationKeyOneRound(rlk_aggregate2, rlk)

		srlk, err := rlk.MarshalBinary()
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("srlk", srlk)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().PutState("state", []byte{state[0] + 2})
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}
		
		err = ctx.GetStub().SetEvent("srlk", []byte("srlk"))
		if err != nil {
			return fmt.Errorf("failed to SetEvent. %v", err)
		}
		return ctx.GetStub().PutState("count", []byte{0})
	}else{
		err = ctx.GetStub().PutState("1"+fmt.Sprintf("%d", id), []byte(data))
		if err != nil {
			return err
		}
		return ctx.GetStub().PutState("count", []byte{count[0]})
	}
}

func (s *SmartContract) EncryptAndEval(ctx contractapi.TransactionContextInterface) (err error) {
	srlk, err := ctx.GetStub().GetState("srlk")
	if err != nil {
		return err
	}
	rlk := rlwe.NewRelinearizationKey(s.params.Parameters, 2)
	err = rlk.UnmarshalBinary(srlk)
	if err != nil {
		return err
	}

	sdata, err := ctx.GetStub().GetState("data")
	if err != nil {
		return err
	}
	data := new(rlwe.Ciphertext)
	err = data.UnmarshalBinary(sdata)
	if err != nil {
		return err
	}

	evaluator := ckks.NewEvaluator(s.params, rlwe.EvaluationKey{Rlk: rlk})
	result := evaluator.MulRelinNew(data, data)
	sresult, err := result.MarshalBinary()
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState("level", []byte(fmt.Sprintf("%d", result.Level())))
	if err != nil {
		return err
	}

	err = ctx.GetStub().SetEvent("sresult", sresult)
	if err != nil {
		return fmt.Errorf("failed to SetEvent. %v", err)
	}
	return ctx.GetStub().PutState("sresult", sresult)
}

func (s *SmartContract) KeySwitch(ctx contractapi.TransactionContextInterface, id int, data string) error {
	if id < 0 || id >= s.N {
		return fmt.Errorf("the user %d doesn't exist", id)
	}
	exist, err := ctx.GetStub().GetState("3"+fmt.Sprintf("%d", id))
	if err != nil {
		return err
	}
	if exist != nil {
		return fmt.Errorf("the data %d already exists", id)
	}

	state, err := ctx.GetStub().GetState("state")
	if err != nil {
		return err
	}
	if state[0] != 3 {
		return fmt.Errorf("the state is wrong")
	}

	count, err := ctx.GetStub().GetState("count")
	if err != nil {
		return err
	}
	count[0] += 1

	l, err := ctx.GetStub().GetState("level")
	if err != nil {
		return err
	}
	level, err := strconv.Atoi(string(l))
	if err != nil {
		return err
	}

	if int(count[0]) == s.N {
		sw_aggregate := s.pcks.AllocateShare(level)
		for i := 0; i < s.N; i++ {
			var ssw_share []byte
			if i != id {
				ssw_share, err = ctx.GetStub().GetState("3"+fmt.Sprintf("%d", i))
				if err != nil {
					return err
				}
			}else {
				ssw_share = []byte(data)
			}
			sw_share := new(drlwe.PCKSShare)
			err = sw_share.UnmarshalBinary(ssw_share)
			if err != nil {
				return err
			}
			s.pcks.AggregateShares(sw_aggregate, sw_share, sw_aggregate)
		}
		
		sresult, err := ctx.GetStub().GetState("sresult")
		if err != nil {
			return err
		}

		result := new(rlwe.Ciphertext)
		err = result.UnmarshalBinary(sresult)
		if err != nil {
			return err
		}

		sw_result := ckks.NewCiphertext(s.params, 1, level)
		s.pcks.KeySwitch(result, sw_aggregate, sw_result)
		ssw_result, err := sw_result.MarshalBinary()
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("ssw_result", ssw_result)
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().PutState("state", []byte{state[0] + 1})
		if err != nil {
			return fmt.Errorf("failed to put to world state. %v", err)
		}

		err = ctx.GetStub().SetEvent("ssw_result", ssw_result)
		if err != nil {
			return fmt.Errorf("failed to SetEvent. %v", err)
		}
		return ctx.GetStub().PutState("count", []byte{0})
	}else{
		err = ctx.GetStub().PutState("3"+fmt.Sprintf("%d", id), []byte(data))
		if err != nil {
			return err
		}
		return ctx.GetStub().PutState("count", []byte{count[0]})
	}
}

func (s *SmartContract) FheAdd(ctx contractapi.TransactionContextInterface, param, lhs, rhs string) (string, error) {
	var x, y rlwe.Ciphertext
	err := x.UnmarshalBinary([]byte(lhs))
	if err != nil {
		return "", err
	}
	err = y.UnmarshalBinary([]byte(rhs))
	if err != nil {
		return "", err
	}
	params, err := ParametersFromString(param)
	if err != nil {
		return "", err
	}
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: nil})
	result := evaluator.AddNew(&x, &y)
	res, err := result.MarshalBinary()
	return string(res), err
}

func (s *SmartContract) FheSub(ctx contractapi.TransactionContextInterface, param, lhs, rhs string) (string, error) {
	var x, y rlwe.Ciphertext
	err := x.UnmarshalBinary([]byte(lhs))
	if err != nil {
		return "", err
	}
	err = y.UnmarshalBinary([]byte(rhs))
	if err != nil {
		return "", err
	}
	params, err := ParametersFromString(param)
	if err != nil {
		return "", err
	}
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: nil})
	result := evaluator.SubNew(&x, &y)
	res, err := result.MarshalBinary()
	return string(res), err
}

func (s *SmartContract) FheMul(ctx contractapi.TransactionContextInterface, param, rlk, lhs, rhs string) (string, error) {
	var x, y rlwe.Ciphertext
	var k rlwe.RelinearizationKey
	err := k.UnmarshalBinary([]byte(rlk))
	if err != nil {
		return "", err
	}
	err = x.UnmarshalBinary([]byte(lhs))
	if err != nil {
		return "", err
	}
	err = y.UnmarshalBinary([]byte(rhs))
	if err != nil {
		return "", err
	}
	params, err := ParametersFromString(param)
	if err != nil {
		return "", err
	}
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: &k})
	result := evaluator.MulRelinNew(&x, &y)
	_ = evaluator.Rescale(result, params.DefaultScale(), result)
	res, err := result.MarshalBinary()
	return string(res), err
}


func (s *SmartContract) ReadNomask(ctx contractapi.TransactionContextInterface) error {
	var x rlwe.Ciphertext
	data, _ := ctx.GetStub().GetState("nomask")
	err := x.UnmarshalBinary(data)
	return err
}

func (s *SmartContract) ReadMask(ctx contractapi.TransactionContextInterface, cipher string, masktype string)error {
	params, _ := ParametersFromString("PN12QP109CI")
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: nil})
	var x rlwe.Ciphertext
	err := x.UnmarshalBinary(s.mask)
	if masktype == "mask32768"{
		mask32768, _ := ctx.GetStub().GetState("mask32768")
		values := make([]float64,params.Slots())
		for i:=0;i<params.Slots();i++{
			values[i]=math.Float64frombits(binary.LittleEndian.Uint64(mask32768[8*i:8*i+8]))
		}
		encoder := ckks.NewEncoder(params)
		plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
		evaluator.Add(&x,plaintext,&x)
	}else{
		mask8, _ := ctx.GetStub().GetState("mask8")
		evaluator.AddConst(&x, math.Float64frombits(binary.LittleEndian.Uint64(mask8)), &x)
	}

	return err
}

func (s *SmartContract) SetAsset(ctx contractapi.TransactionContextInterface, key string, data string) error{
	err := ctx.GetStub().PutState(key, []byte(data))
	return err
}

func (s *SmartContract) Plain(ctx contractapi.TransactionContextInterface, method string, key string) error{
	switch method{
	case "Add":
		mask8, _ := ctx.GetStub().GetState("mask8")
		mask8, _ = ctx.GetStub().GetState("mask8")
		x := math.Float64frombits(binary.LittleEndian.Uint64(mask8))
		y := math.Float64frombits(binary.LittleEndian.Uint64(mask8))
		mask8 = make([]byte, 8)
		bits := math.Float64bits(x+y)
		binary.LittleEndian.PutUint64(mask8, bits)
		_ = ctx.GetStub().PutState(key, mask8)
	case "Mul":
		mask8, _ := ctx.GetStub().GetState("mask8")
		mask8, _ = ctx.GetStub().GetState("mask8")
		x := math.Float64frombits(binary.LittleEndian.Uint64(mask8))
		y := math.Float64frombits(binary.LittleEndian.Uint64(mask8))
		mask8 = make([]byte, 8)
		bits := math.Float64bits(x*y)
		binary.LittleEndian.PutUint64(mask8, bits)
		_ = ctx.GetStub().PutState(key, mask8)
	}
	return nil
}

func (s *SmartContract) Lattigo(ctx contractapi.TransactionContextInterface, literal string, method string, key string) error{
	params, _ := ParametersFromString(literal)
	i:=0
	if literal=="PN12QP109"{
		i = 0
	}
	if literal=="PN13QP218"{
		i = 1
	}
	switch method{
	case "Add":
		var ciphertext1, ciphertext2 rlwe.Ciphertext
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		sciphertext2, _ := ctx.GetStub().GetState("sciphertext2"+literal)
		_ = ciphertext2.UnmarshalBinary(sciphertext2)
		s.evaluator[i].Add(&ciphertext1, &ciphertext2, &ciphertext1)
		ctx.GetStub().PutState(key, sciphertext1)
	case "AddScalar":
		var ciphertext1 rlwe.Ciphertext
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		s.evaluator[i].AddConst(&ciphertext1, complex(3.1415, -1.4142), &ciphertext1)
		ctx.GetStub().PutState(key, sciphertext1)
	case "Mul":
		var ciphertext1, ciphertext2 rlwe.Ciphertext
		receiver := rlwe.NewCiphertext(params.Parameters, 2, params.MaxLevel())
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		sciphertext2, _ := ctx.GetStub().GetState("sciphertext2"+literal)
		_ = ciphertext2.UnmarshalBinary(sciphertext2)
		s.evaluator[i].Mul(&ciphertext1, &ciphertext2, receiver)
		ctx.GetStub().PutState(key, sciphertext1)
	case "MulPlain":
		var ciphertext1 rlwe.Ciphertext
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		plaintext := ckks.NewPlaintext(params, params.MaxLevel())
		s.evaluator[i].Mul(&ciphertext1, plaintext, &ciphertext1)
		ctx.GetStub().PutState(key, sciphertext1)
	case "MulScalar":
		var ciphertext1 rlwe.Ciphertext
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		s.evaluator[i].MultByConst(&ciphertext1, complex(3.1415, -1.4142), &ciphertext1)
		ctx.GetStub().PutState(key, sciphertext1)
	case "Relin":
		var receiver rlwe.Ciphertext
		ciphertext1 := rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel())
		sreceiver, _ := ctx.GetStub().GetState("sreceiver"+literal)
		_ = receiver.UnmarshalBinary(sreceiver)
		s.evaluator[i].Relinearize(&receiver, ciphertext1)
		sciphertext1, _ := ciphertext1.MarshalBinary()
		ctx.GetStub().PutState(key, make([]byte,len(sciphertext1)))
	case "Rescale":
		var ciphertext1 rlwe.Ciphertext
		ciphertext2 := rlwe.NewCiphertext(params.Parameters, 1, params.MaxLevel())
		sciphertext1, _ := ctx.GetStub().GetState("sciphertext1"+literal)
		_ = ciphertext1.UnmarshalBinary(sciphertext1)
		ciphertext1.Scale = params.DefaultScale().Mul(params.DefaultScale())
		s.evaluator[i].Rescale(&ciphertext1, params.DefaultScale(), ciphertext2)
		ctx.GetStub().PutState(key, sciphertext1)
	}
	return nil
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
		return []byte{}, fmt.Errorf("RKGCRP : uint8 overflow on length")
	}

	if len(crp_rlk[0]) > 0xFF {
		return []byte{}, fmt.Errorf("RKGCRP : uint8 overflow on length")
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