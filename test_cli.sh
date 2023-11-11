#!/bin/bash
echo "run the demo!"

test_chaincode(){
    cd ../fhe-go/chaincode-go
    rm -r vendor
    GO111MODULE=on go mod vendor
    go get github.com/tuneinsight/lattigo/v4/ckks
    go get github.com/tuneinsight/lattigo/v4/rlwe
    go get github.com/gobuffalo/envy@v1.10.1
    cd ../../test-network
}
test_up(){
    ./network.sh up
}
test_createChannel(){
    ./network.sh createChannel -c mychannel
}
test_install(){
    peer lifecycle chaincode package basic.tar.gz --path ../fhe-go/chaincode-go/ --lang golang --label basic_1.0
    export CORE_PEER_TLS_ENABLED=true
    export CORE_PEER_LOCALMSPID="Org1MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
    export CORE_PEER_ADDRESS=localhost:7051
    peer lifecycle chaincode install basic.tar.gz
    export CORE_PEER_LOCALMSPID="Org2MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
    export CORE_PEER_ADDRESS=localhost:9051
    peer lifecycle chaincode install basic.tar.gz
}
test_approve(){
    package_id=$(peer lifecycle chaincode queryinstalled | grep -o -E "[0-9a-f]{64}")
    export CC_PACKAGE_ID=basic_1.0:$package_id
    echo $package_id
    
    export CORE_PEER_LOCALMSPID="Org2MSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
    export CORE_PEER_ADDRESS=localhost:9051
    peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --channelID mychannel --name basic --version 1.0 --package-id $CC_PACKAGE_ID --sequence 1 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
    export CORE_PEER_LOCALMSPID="Org1MSP"
    export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
    export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
    export CORE_PEER_ADDRESS=localhost:7051
    peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --channelID mychannel --name basic --version 1.0 --package-id $CC_PACKAGE_ID --sequence 1 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
}
test_commit(){
    peer lifecycle chaincode checkcommitreadiness --channelID mychannel --name basic --version 1.0 --sequence 1 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --output json
    peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --channelID mychannel --name basic --version 1.0 --sequence 1 --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
    peer lifecycle chaincode querycommitted --channelID mychannel --name basic --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
}
test_invoke(){
    peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n basic --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt" -c '{"function":"InitLedger","Args":[]}'
}
test_query(){
    peer chaincode query -C mychannel -n basic -c '{"Args":["GetAllAssets"]}'
}
test_down(){
    ./network.sh down
}


go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn
cd $HOME/go/src/github.com/lcc1999/fabric-samples/test-network
if [ "$1" = "chaincode" ]
then
  test_chaincode
 
elif [ "$1" = "up" ]
then
  test_up

elif [ "$1" = "createChannel" ]
then
  test_createChannel

elif [ "$1" = "install" ]
then
  test_install

elif [ "$1" = "approve" ]
then
  test_approve

elif [ "$1" = "commit" ]
then
  test_commit

elif [ "$1" = "invoke" ]
then
  test_invoke

elif [ "$1" = "query" ]
then
  test_query

elif [ "$1" = "down" ]
then
  test_down

else
  test_chaincode
  test_up
  test_createChannel
  test_install
  test_approve
  test_commit
  test_invoke
  test_query
  test_down
fi