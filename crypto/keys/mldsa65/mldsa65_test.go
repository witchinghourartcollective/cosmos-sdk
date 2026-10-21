package mldsa65_test

import (
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

func TestSignVerify(t *testing.T) {
	priv := mldsa65.GenPrivKey()
	pub := priv.PubKey()

	msg := []byte("hour-chain consensus vote")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if len(sig) != mldsa65.SignatureSize {
		t.Fatalf("signature size = %d, want %d", len(sig), mldsa65.SignatureSize)
	}
	if !pub.VerifySignature(msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if pub.VerifySignature([]byte("different message"), sig) {
		t.Fatal("signature verified against the wrong message")
	}
}

func TestCometBFTProtoRoundTrip(t *testing.T) {
	priv := mldsa65.GenPrivKey()
	pub := priv.PubKey()

	proto, err := codec.ToCmtProtoPublicKey(pub)
	if err != nil {
		t.Fatalf("ToCmtProtoPublicKey failed: %v", err)
	}
	if proto.GetMlDsa65() == nil {
		t.Fatal("expected PublicKey_MlDsa65 in proto oneof, got something else")
	}

	back, err := codec.FromCmtProtoPublicKey(proto)
	if err != nil {
		t.Fatalf("FromCmtProtoPublicKey failed: %v", err)
	}
	if !pub.Equals(back) {
		t.Fatal("round-tripped pubkey does not equal original")
	}
}

func TestCometBFTPubKeyInterfaceRoundTrip(t *testing.T) {
	priv := mldsa65.GenPrivKey()
	pub := priv.PubKey()

	cmtPub, err := codec.ToCmtPubKeyInterface(pub)
	if err != nil {
		t.Fatalf("ToCmtPubKeyInterface failed: %v", err)
	}

	back, err := codec.FromCmtPubKeyInterface(cmtPub)
	if err != nil {
		t.Fatalf("FromCmtPubKeyInterface failed: %v", err)
	}
	if !pub.Equals(back) {
		t.Fatal("pubkey does not survive a full ToCmtPubKeyInterface/FromCmtPubKeyInterface round-trip")
	}
}

func TestProtoWireMarshalUnmarshal(t *testing.T) {
	priv := mldsa65.GenPrivKey()
	pub := priv.PubKey().(*mldsa65.PubKey)

	wire, err := pub.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded mldsa65.PubKey
	if err := decoded.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	var pk cryptotypes.PubKey = &decoded
	if !pub.Equals(pk) {
		t.Fatal("pubkey does not survive a real proto wire Marshal/Unmarshal round-trip")
	}
}
