module github.com/lcc1999/fabric-samples/fhe-go/mpfhe

go 1.20

require github.com/tuneinsight/lattigo/v4 v4.1.0

require (
	golang.org/x/crypto v0.0.0-20220926161630-eccd6366d1be // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
)

replace github.com/tuneinsight/lattigo/v4 => ../lattigo
