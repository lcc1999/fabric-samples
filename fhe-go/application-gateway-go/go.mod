module assetTransfer

go 1.18

require (
	github.com/hyperledger/fabric-gateway v1.2.2
	github.com/hyperledger/fabric-protos-go-apiv2 v0.2.0
	github.com/tuneinsight/lattigo/v4 v4.1.0
	google.golang.org/grpc v1.53.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	google.golang.org/genproto v0.0.0-20230216225411-c8e22ba71e44 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
)

replace github.com/tuneinsight/lattigo/v4 => ../lattigo
