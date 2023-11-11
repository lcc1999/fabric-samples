#!/bin/bash
export PATH=$PATH:/usr/local/go/bin
echo "run the demo!"

test_chaincode(){
    cd ../fhe-go/chaincode-go
    rm -r vendor
    
    GO111MODULE=on go mod vendor
    go mod edit -replace github.com/tuneinsight/lattigo/v4=../lattigo
    #go get github.com/tuneinsight/lattigo/v4/ckks
    #go get github.com/tuneinsight/lattigo/v4/rlwe
    #go get github.com/gobuffalo/envy@v1.10.1
    cd ../../test-network
}
test_start(){
    ./network.sh up createChannel -c mychannel -ca
    ./network.sh deployCC -ccn basic -ccp ../fhe-go/chaincode-go/ -ccl go
}
test_sdk(){
    cd ../fhe-go/application-gateway-go
    go mod edit -replace github.com/tuneinsight/lattigo/v4=../lattigo
    go mod tidy
    # for ((i=1;i<=2;i++)) 
    # do
    #   if [ i = 1 ]
    #   then
    #     (go run assetTransfer1.go &> log1.txt)&
    #   else
    #     (echo "1" &> log2.txt)& #(go run assetTransfer2.go &> log2.txt)&
    #   fi
    # done
    # wait
    #go run assetTransfer1.go &> log1.txt
    go run assetTransfer.go
    cd ../../test-network
}
test_end(){
    ./network.sh down
}

go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn
cd $HOME/lcc/go/src/github.com/lcc1999/fabric-samples/test-network
if [ "$1" = "chaincode" ]
then
  test_chaincode

elif [ "$1" = "start" ]
then
  test_start

elif [ "$1" = "sdk" ]
then
  test_sdk

elif [ "$1" = "end" ]
then
  test_end

else
  test_chaincode
  test_start
  test_sdk
  test_end
fi