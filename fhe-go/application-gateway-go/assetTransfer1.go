/*
Copyright 2021 IBM All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

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
	mspID        = "Org1MSP"
	cryptoPath   = "../../test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"

	N = 2
	seed = "test"
	literal = "PN13QP218"//"PN12QP109", "PN12QP109CI", "PN13QP218", "PN13QP218CI"
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
	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity()
	sign := newSign()

	// Create a Gateway connection for a specific client identity
	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gw.Close()

	// Override default values for chaincode and channel name as they may differ in testing contexts.
	chaincodeName := "basic"
	if ccname := os.Getenv("CHAINCODE_NAME"); ccname != "" {
		chaincodeName = ccname
	}

	channelName := "mychannel"
	if cname := os.Getenv("CHANNEL_NAME"); cname != "" {
		channelName = cname
	}

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)

	// Context used for event listening
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for events emitted by subsequent transactions
	startChaincodeEventListening(ctx, network, chaincodeName, contract)

	params, _ = ParametersFromString(literal)
	kgen = ckks.NewKeyGenerator(params)
	computer.sk, computer.pk = kgen.GenKeyPair()
	computer.parties = make([]PartyPub, N)
	encoder = ckks.NewEncoder(params)
	crs, _ = utils.NewKeyedPRNG([]byte(seed))

	initLedger(contract)
	/*getAllAssets(contract)
	createAsset(contract)
	readAssetByID(contract)
	transferAssetAsync(contract)
	exampleErrorHandling(contract)*/
	/*for _, param := range  []string{"PN12QP109", "PN13QP218", "PN14QP438", "PN15QP880", "PN12QP109CI", "PN13QP218CI", "PN14QP438CI", "PN15QP880CI"}{
		print(param)
		fheAdd(contract,param)
	}
	for _, param := range  []string{"PN12QP109", "PN12QP109CI", "PN13QP218", "PN13QP218CI"}{
		print(param)
		fheMul(contract,param)
	}*/
	replayChaincodeEvents(ctx, network, uint64(0), chaincodeName)
	downloadAndDecrypt(contract)
}

func startChaincodeEventListening(ctx context.Context, network *client.Network, chaincodeName string, contract *client.Contract) {
	fmt.Println("\n*** Start chaincode event listening")

	events, err := network.ChaincodeEvents(ctx, chaincodeName)
	if err != nil {
		panic(fmt.Errorf("failed to start chaincode event listening: %w", err))
	}

	go func() {
		for event := range events {
			i := 0
			payload := event.Payload
			switch event.EventName {
			case "spk":
				parties[i].pk = new(rlwe.PublicKey)
				_ = parties[i].pk.UnmarshalBinary(payload)

				fmt.Printf("\n--> Submit Transaction: CpkGen, function returns the result\n")

				parties[i].sk = kgen.GenSecretKey()
				parties[i].pk_share = ckg.AllocateShare()
				parties[i].cpk = rlwe.NewPublicKey(params.Parameters)
				evaluateResult, err := contract.EvaluateTransaction("GetData", "scrp_pk")
				if err != nil {
					// panic(fmt.Errorf("failed to evaluate transaction: %w", err))
					fmt.Println("failed to evaluate transaction: %w", err)
					for {
						evaluateResult, err = contract.EvaluateTransaction("GetData", "scrp_pk")
						if err == nil {
							break
						}
					}
				}
				crp_pk, _ := CKGCRPUnmarshalBinary(evaluateResult)
				ckg.GenShare(parties[i].sk, crp_pk, parties[i].pk_share)
				computer.parties[i].spk_share, _ = parties[i].pk_share.MarshalBinary()

				_, err = contract.SubmitTransaction("CpkGen", fmt.Sprintf("%d", i), string(computer.parties[i].spk_share))
				if err != nil {
					// panic(fmt.Errorf("failed to submit transaction: %w", err))
					fmt.Println("failed to submit transaction: %w", err)
					for {
						_, err = contract.SubmitTransaction("CpkGen", fmt.Sprintf("%d", i), string(computer.parties[i].spk_share))
						if err == nil {
							break
						}
					}
				}
				
			case "scpk":
				
				_ = parties[i].cpk.UnmarshalBinary(payload)
				fmt.Printf("\n--> Submit Transaction: RlkGen, function returns the result\n")
				parties[i].rlk_secret, parties[i].rlk_share1, parties[i].rlk_share2 = rkg.AllocateShare()
				rkg.GenShare(parties[i].sk, parties[i].cpk, parties[i].rlk_share1)
				computer.parties[i].srlk_share1, _ = parties[i].rlk_share1.MarshalBinary()

				_, err = contract.SubmitTransaction("RlkGen", fmt.Sprintf("%d", i), string(computer.parties[i].srlk_share1))
				if err != nil {
					// panic(fmt.Errorf("failed to submit transaction: %w", err))
					fmt.Println("failed to submit transaction: %w", err)
					for {
						_, err = contract.SubmitTransaction("RlkGen", fmt.Sprintf("%d", i), string(computer.parties[i].srlk_share1))
						if err == nil {
							break
						}
					}
				}
				_, computer.rlk_aggregate1, computer.rlk_aggregate2 = rkg.AllocateShare()
			// case "scpk":
			// 	for i := 0; i < N; i++ {
			// 		_ = parties[i].cpk.UnmarshalBinary(payload)
			// 	}
			// 	fmt.Printf("\n--> Submit Transaction: RlkGen1, function returns the result\n")
			// 	for i := 0; i < N; i++ {
			// 		parties[i].rlk_secret, parties[i].rlk_share1, parties[i].rlk_share2 = rkg.AllocateShare()
			// 		evaluateResult, err := contract.EvaluateTransaction("GetData", "scrp_rlk")
			// 		if err != nil {
			// 			panic(fmt.Errorf("failed to evaluate transaction: %w", err))
			// 		}
			// 		crp_rlk, _ := RKGCRPUnmarshalBinary(evaluateResult)
			// 		rkg.GenShareRoundOne(parties[i].sk, crp_rlk, parties[i].rlk_secret, parties[i].rlk_share1)
			// 		computer.parties[i].srlk_share1, _ = parties[i].rlk_share1.MarshalBinary()

			// 		_, err = contract.SubmitTransaction("RlkGen1", fmt.Sprintf("%d", i), string(computer.parties[i].srlk_share1))
			// 		if err != nil {
			// 			panic(fmt.Errorf("failed to submit transaction: %w", err))
			// 		}
			// 	}
			// 	_, computer.rlk_aggregate1, computer.rlk_aggregate2 = rkg.AllocateShare()
			// case "srlk_aggregate1":
			// 	computer.rlk_aggregate1 = new(drlwe.RKGShare)
			// 	_ = computer.rlk_aggregate1.UnmarshalBinary(payload)
			// 	fmt.Printf("\n--> Submit Transaction: RlkGen2, function returns the result\n")
			// 	for i := 0; i < N; i++ {
			// 		rkg.GenShareRoundTwo(parties[i].rlk_secret, parties[i].sk, computer.rlk_aggregate1, parties[i].rlk_share2)
			// 		computer.parties[i].srlk_share2, _ = parties[i].rlk_share2.MarshalBinary()

			// 		_, err = contract.SubmitTransaction("RlkGen2", fmt.Sprintf("%d", i), string(computer.parties[i].srlk_share2))
			// 		if err != nil {
			// 			panic(fmt.Errorf("failed to submit transaction: %w", err))
			// 		}
			// 	}
			case "srlk":
				encryptAndEval(contract)
			case "sresult":
				pcks = dckks.NewPCKSProtocol(params, sigmaSmudging)
				result := new(rlwe.Ciphertext)
				_ = result.UnmarshalBinary(payload)
		
				parties[i].sw_share = pcks.AllocateShare(result.Level())
				pcks.GenShare(parties[i].sk, parties[i].pk, result, parties[i].sw_share)
				computer.parties[i].ssw_share, _ = parties[i].sw_share.MarshalBinary()
		
				_, err = contract.SubmitTransaction("KeySwitch", fmt.Sprintf("%d", i), string(computer.parties[i].ssw_share))
				if err != nil {
					// panic(fmt.Errorf("failed to submit transaction: %w", err))
					fmt.Println("failed to submit transaction: %w", err)
					for {
						_, err = contract.SubmitTransaction("KeySwitch", fmt.Sprintf("%d", i), string(computer.parties[i].ssw_share))
						if err == nil {
							break
						}
					}
				}
			}
		}
	}()
}

func replayChaincodeEvents(ctx context.Context, network *client.Network, startBlock uint64, chaincodeName string) {
	fmt.Println("\n*** Start chaincode event replay")

	events, err := network.ChaincodeEvents(ctx, chaincodeName, client.WithStartBlock(startBlock))
	if err != nil {
		panic(fmt.Errorf("failed to start chaincode event listening: %w", err))
	}

	for {
		select {

		case event := <-events:
			payload := event.Payload
			fmt.Printf("\n<-- Chaincode event replayed: %s - %d\n", event.EventName, len(payload))

			if event.EventName == "ssw_result" {
				return
			}
		}
	}
}


// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(20*1024*1024), 
									grpc.MaxCallSendMsgSize(20*1024*1024)))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := os.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := os.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

// This type of transaction would typically only be run once by an application the first time it was started after its
// initial deployment. A new version of the chaincode deployed later would likely not need to run an "init" function.
func initLedger(contract *client.Contract) {
	fmt.Printf("\n--> Submit Transaction: InitLedger, function creates the initial set of assets on the ledger \n")

	ckg = dckks.NewCKGProtocol(params)
	computer.crp_pk = ckg.SampleCRP(crs)
	rkg = dckks.NewRKGProtocol(params)
	computer.crp_rlk = rkg.SampleCRP(crs)

	computer.spk, _ = computer.pk.MarshalBinary()
	computer.scrp_pk, _ =  CKGCRPMarshalBinary(computer.crp_pk)
	computer.scrp_rlk, _ = RKGCRPMarshalBinary(computer.crp_rlk)

	fmt.Println(len(computer.spk),len(computer.scrp_pk),len(computer.scrp_rlk))
	_, err := contract.SubmitTransaction("InitLedger", fmt.Sprintf("%d", N), literal, string(computer.spk), string(computer.scrp_pk))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

func encryptAndEval(contract *client.Contract) {
	fmt.Printf("\n--> Submit Transaction: EncryptAndEval, function returns the result\n")

	// evaluateResult, err := contract.EvaluateTransaction("EncryptAndEval", param, string(rlk), string(lhs), string(rhs))
	// if err != nil {
	// 	panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	// }

	//Party
	encryptor := ckks.NewEncryptor(params, parties[0].cpk)
	values := make([]float64, params.Slots())
	for i := 0; i < params.Slots(); i++{
		values[i] = 3.0
	}
	plaintext := encoder.EncodeNew(values, params.MaxLevel(), params.DefaultScale(), params.LogSlots())
	ciphertext = encryptor.EncryptNew(plaintext)

	sciphertext, _ := ciphertext.MarshalBinary()

	id, err := contract.SubmitTransaction("SetData", "data", string(sciphertext))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}
	fmt.Println(string(id))

	_, err = contract.SubmitTransaction("EncryptAndEval")
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}

	// //Computer
	// ct := new(rlwe.Ciphertext)
	// _ = ct.UnmarshalBinary(sciphertext)
	
	// computer.rlk = rlwe.NewRelinearizationKey(params.Parameters, 2)
	// evaluateResult, err := contract.EvaluateTransaction("GetData", "srlk")
	// if err != nil {
	// 	panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	// }
	// _ = computer.rlk.UnmarshalBinary(evaluateResult)

	// evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: computer.rlk})
	// computer.result = evaluator.MulRelinNew(ct, ct)
	// computer.sresult, _ = computer.result.MarshalBinary()
}

func downloadAndDecrypt(contract *client.Contract) {
	fmt.Printf("\n--> Evaluate Transaction: GetData, function returns the result\n")

	//Computer
	decryptor := ckks.NewDecryptor(params, computer.sk)
	sw_result := new(rlwe.Ciphertext)

	evaluateResult, err := contract.EvaluateTransaction("GetData", "ssw_result")
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	_ = sw_result.UnmarshalBinary(evaluateResult)

	plaintext := decryptor.DecryptNew(sw_result)
	value := encoder.Decode(plaintext, params.LogSlots())
	min,max:=min_max(value)
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
















// Evaluate a transaction to query ledger state.
func getAllAssets(contract *client.Contract) {
	fmt.Println("\n--> Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger")

	evaluateResult, err := contract.EvaluateTransaction("GetAllAssets")
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func createAsset(contract *client.Contract) {
	fmt.Printf("\n--> Submit Transaction: CreateAsset, creates new asset with ID, Color, Size, Owner and AppraisedValue arguments \n")

	_, err := contract.SubmitTransaction("CreateAsset", assetId, "yellow", "5", "Tom", "1300")
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Evaluate a transaction by assetID to query ledger state.
func readAssetByID(contract *client.Contract) {
	fmt.Printf("\n--> Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAsset", assetId)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

func fheAdd(contract *client.Contract, param string) {
	fmt.Printf("\n--> Evaluate Transaction: FheAdd, function returns the result\n")

	params, err := ParametersFromString(param)
	sk, pk, _,_,_ := Keygen(params, []int{1})
	lhs,_ := Encrypt(params, pk, 3.0)
	rhs,_ := Encrypt(params, pk, 2.0)
	start := time.Now()
	evaluateResult, err := contract.EvaluateTransaction("FheAdd", param, string(lhs), string(rhs))
	t := time.Since(start)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result, _ := Decrypt(params, sk, []byte(evaluateResult), 0)

	fmt.Printf("*** Result:%s,time:%s\n", result,t)
}

func fheMul(contract *client.Contract, param string) {
	fmt.Printf("\n--> Evaluate Transaction: FheMul, function returns the result\n")

	params, err := ParametersFromString(param)
	sk, pk, rlk,_,_ := Keygen(params, []int{1})
	lhs,_ := Encrypt(params, pk, 3.0)
	rhs,_ := Encrypt(params, pk, 2.0)
	start := time.Now()
	evaluateResult, err := contract.EvaluateTransaction("FheMul", param, string(rlk), string(lhs), string(rhs))
	t := time.Since(start)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result, _ := Decrypt(params, sk, []byte(evaluateResult), 0)

	fmt.Printf("*** Result:%s,time:%s\n", result,t)
}

// Submit transaction asynchronously, blocking until the transaction has been sent to the orderer, and allowing
// this thread to process the chaincode response (e.g. update a UI) without waiting for the commit notification
func transferAssetAsync(contract *client.Contract) {
	fmt.Printf("\n--> Async Submit Transaction: TransferAsset, updates existing asset owner")

	submitResult, commit, err := contract.SubmitAsync("TransferAsset", client.WithArguments(assetId, "Mark"))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction asynchronously: %w", err))
	}

	fmt.Printf("\n*** Successfully submitted transaction to transfer ownership from %s to Mark. \n", string(submitResult))
	fmt.Println("*** Waiting for transaction commit.")

	if commitStatus, err := commit.Status(); err != nil {
		panic(fmt.Errorf("failed to get commit status: %w", err))
	} else if !commitStatus.Successful {
		panic(fmt.Errorf("transaction %s failed to commit with status: %d", commitStatus.TransactionID, int32(commitStatus.Code)))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Submit transaction, passing in the wrong number of arguments ,expected to throw an error containing details of any error responses from the smart contract.
func exampleErrorHandling(contract *client.Contract) {
	fmt.Println("\n--> Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error")

	_, err := contract.SubmitTransaction("UpdateAsset", "asset70", "blue", "5", "Tomoko", "300")
	if err == nil {
		panic("******** FAILED to return an error")
	}

	fmt.Println("*** Successfully caught the error:")

	switch err := err.(type) {
	case *client.EndorseError:
		fmt.Printf("Endorse error for transaction %s with gRPC status %v: %s\n", err.TransactionID, status.Code(err), err)
	case *client.SubmitError:
		fmt.Printf("Submit error for transaction %s with gRPC status %v: %s\n", err.TransactionID, status.Code(err), err)
	case *client.CommitStatusError:
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
		} else {
			fmt.Printf("Error obtaining commit status for transaction %s with gRPC status %v: %s\n", err.TransactionID, status.Code(err), err)
		}
	case *client.CommitError:
		fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
	default:
		panic(fmt.Errorf("unexpected error type %T: %w", err, err))
	}

	// Any error that originates from a peer or orderer node external to the gateway will have its details
	// embedded within the gRPC status error. The following code shows how to extract that.
	statusErr := status.Convert(err)

	details := statusErr.Details()
	if len(details) > 0 {
		fmt.Println("Error Details:")

		for _, detail := range details {
			switch detail := detail.(type) {
			case *gateway.ErrorDetail:
				fmt.Printf("- address: %s, mspId: %s, message: %s\n", detail.Address, detail.MspId, detail.Message)
			}
		}
	}
}