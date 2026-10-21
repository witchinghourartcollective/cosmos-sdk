package codec_test

import (
	"testing"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
)

// TestMlDsa65RegisteredAsAny confirms mldsa65.PubKey/PrivKey are registered
// implementations of cryptotypes.PubKey/PrivKey, exercised through the same
// proto Any pack/unpack path x/staking's MsgCreateValidator uses for its
// validator pubkey field -- not just an in-memory type assertion.
func TestMlDsa65RegisteredAsAny(t *testing.T) {
	registry := codectypes.NewInterfaceRegistry()
	codec.RegisterInterfaces(registry)

	priv := mldsa65.GenPrivKey()
	pub := priv.PubKey()

	any, err := codectypes.NewAnyWithValue(pub)
	if err != nil {
		t.Fatalf("NewAnyWithValue failed: %v", err)
	}

	var unpacked cryptotypes.PubKey
	if err := registry.UnpackAny(any, &unpacked); err != nil {
		t.Fatalf("UnpackAny failed -- mldsa65.PubKey likely not registered: %v", err)
	}
	if !pub.Equals(unpacked) {
		t.Fatal("pubkey does not survive a real registry Any pack/unpack round-trip")
	}
}
