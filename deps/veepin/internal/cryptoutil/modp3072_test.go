package cryptoutil

import (
	"bytes"
	"math/big"
	"testing"
)

func TestMODP3072AgreementAndWireSize(t *testing.T) {
	a, b := NewMODP3072(), NewMODP3072()
	apub, err := a.Generate()
	if err != nil {
		t.Fatal(err)
	}
	bpub, err := b.Generate()
	if err != nil {
		t.Fatal(err)
	}
	as, err := a.ComputeSecret(bpub)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := b.ComputeSecret(apub)
	if err != nil {
		t.Fatal(err)
	}
	if len(apub) != 384 || len(bpub) != 384 || len(as) != 384 || len(bs) != 384 || !bytes.Equal(as, bs) {
		t.Fatal("MODP-3072 wire size or shared-secret agreement is incorrect")
	}
}

func TestMODP3072ParametersAndInvalidPeerValues(t *testing.T) {
	if modp3072Prime.BitLen() != 3072 || !modp3072Prime.ProbablyPrime(32) {
		t.Fatal("group 15 modulus is not a 3072-bit prime")
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(modp3072Prime, big.NewInt(1)), 1)
	if !q.ProbablyPrime(32) || new(big.Int).Exp(big.NewInt(2), q, modp3072Prime).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("group 15 is not the expected safe-prime group with generator 2")
	}
	g := NewMODP3072()
	if _, err := g.ComputeSecret([]byte{2}); err == nil {
		t.Fatal("secret computed before generating a private key")
	}
	if _, err := g.Generate(); err != nil {
		t.Fatal(err)
	}
	for _, peer := range [][]byte{
		nil, {0}, {1},
		new(big.Int).Sub(modp3072Prime, big.NewInt(1)).Bytes(),
		modp3072Prime.Bytes(),
		new(big.Int).Add(modp3072Prime, big.NewInt(1)).Bytes(),
	} {
		if _, err := g.ComputeSecret(peer); err == nil {
			t.Fatal("accepted degenerate MODP-3072 peer value")
		}
	}
}
