// Package mldsa65 implements cryptotypes.PubKey/PrivKey for FIPS 204
// ML-DSA-65 (k=6, l=5) via cloudflare/circl, as the cosmos-sdk-side half of
// hOUR Chain's fork toward making ML-DSA an actual CometBFT consensus
// signature type -- see cometbft's crypto/mldsa65 (the CometBFT-side half)
// and hOUR-Chain's docs/GENESIS-DECISION-GATE.md "1b".
package mldsa65

import (
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"

	errorsmod "cosmossdk.io/errors"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

const (
	PrivKeyName = "tendermint/PrivKeyMlDsa65"
	PubKeyName  = "tendermint/PubKeyMlDsa65"

	// PubKeySize is the size, in bytes, of ML-DSA-65 public keys.
	PubKeySize = mldsa65.PublicKeySize
	// PrivKeySize is the size, in bytes, of circl's packed ML-DSA-65
	// private-key representation (not just a seed).
	PrivKeySize = mldsa65.PrivateKeySize
	// SignatureSize is the size, in bytes, of an ML-DSA-65 signature.
	SignatureSize = mldsa65.SignatureSize
	// SeedSize is the size, in bytes, of the seed GenPrivKeyFromSeed expects.
	SeedSize = mldsa65.SeedSize

	KeyType = "mldsa65"
)

var (
	_ cryptotypes.PrivKey  = &PrivKey{}
	_ codec.AminoMarshaler = &PrivKey{}
)

// Bytes returns the privkey byte format.
func (privKey *PrivKey) Bytes() []byte {
	return privKey.Key
}

// Sign produces an ML-DSA-65 signature on the provided message.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	if len(privKey.Key) != PrivKeySize {
		return nil, fmt.Errorf("mldsa65: privkey has incorrect size %d, want %d", len(privKey.Key), PrivKeySize)
	}

	var sk mldsa65.PrivateKey
	var buf [PrivKeySize]byte
	copy(buf[:], privKey.Key)
	sk.Unpack(&buf)

	sig := make([]byte, SignatureSize)
	if err := mldsa65.SignTo(&sk, msg, nil, false, sig); err != nil {
		return nil, fmt.Errorf("mldsa65: sign failed: %w", err)
	}
	return sig, nil
}

// PubKey derives the corresponding public key from the private key.
func (privKey *PrivKey) PubKey() cryptotypes.PubKey {
	if len(privKey.Key) != PrivKeySize {
		panic("mldsa65: privkey has incorrect size")
	}

	var sk mldsa65.PrivateKey
	var buf [PrivKeySize]byte
	copy(buf[:], privKey.Key)
	sk.Unpack(&buf)

	pk := sk.Public().(*mldsa65.PublicKey)
	return &PubKey{Key: pk.Bytes()}
}

// Equals runs in constant time based on length of the keys.
func (privKey *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	if privKey.Type() != other.Type() {
		return false
	}
	return subtle.ConstantTimeCompare(privKey.Bytes(), other.Bytes()) == 1
}

func (privKey *PrivKey) Type() string {
	return KeyType
}

// MarshalAmino overrides Amino binary marshaling.
func (privKey PrivKey) MarshalAmino() ([]byte, error) {
	return privKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshaling.
func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PrivKeySize {
		return fmt.Errorf("invalid privkey size")
	}
	privKey.Key = bz
	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) {
	return privKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error {
	return privKey.UnmarshalAmino(bz)
}

// GenPrivKey generates a new ML-DSA-65 private key.
// These keys must not be used in SDK apps except in a CometBFT
// validator context.
func GenPrivKey() *PrivKey {
	return genPrivKey(crypto.CReader())
}

func genPrivKey(rand io.Reader) *PrivKey {
	_, sk, err := mldsa65.GenerateKey(rand)
	if err != nil {
		panic(err)
	}
	return &PrivKey{Key: sk.Bytes()}
}

// GenPrivKeyFromSeed deterministically derives a key pair from a
// SeedSize-byte seed.
func GenPrivKeyFromSeed(seed []byte) *PrivKey {
	if len(seed) != SeedSize {
		panic("mldsa65: seed has incorrect size")
	}
	var seedBuf [SeedSize]byte
	copy(seedBuf[:], seed)
	_, sk := mldsa65.NewKeyFromSeed(&seedBuf)
	return &PrivKey{Key: sk.Bytes()}
}

//-------------------------------------

var (
	_ cryptotypes.PubKey   = &PubKey{}
	_ codec.AminoMarshaler = &PubKey{}
)

// Address is the SHA256-20 of the raw pubkey bytes. It doesn't implement
// ADR-28 addresses and it must not be used in SDK except in a CometBFT
// validator context.
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("mldsa65: pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubKey.Key))
}

// Bytes returns the PubKey byte format.
func (pubKey *PubKey) Bytes() []byte {
	return pubKey.Key
}

func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(pubKey.Key) != PubKeySize || len(sig) != SignatureSize {
		return false
	}

	var pk mldsa65.PublicKey
	var buf [PubKeySize]byte
	copy(buf[:], pubKey.Key)
	pk.Unpack(&buf)

	return mldsa65.Verify(&pk, msg, nil, sig)
}

// String returns the Hex representation of a pubkey with its type.
func (pubKey *PubKey) String() string {
	return fmt.Sprintf("PubKeyMlDsa65{%X}", pubKey.Key)
}

func (pubKey *PubKey) Type() string {
	return KeyType
}

func (pubKey *PubKey) Equals(other cryptotypes.PubKey) bool {
	if pubKey.Type() != other.Type() {
		return false
	}
	return subtle.ConstantTimeCompare(pubKey.Bytes(), other.Bytes()) == 1
}

// MarshalAmino overrides Amino binary marshaling.
func (pubKey PubKey) MarshalAmino() ([]byte, error) {
	return pubKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshaling.
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errorsmod.Wrap(errors.ErrInvalidPubKey, "invalid pubkey size")
	}
	pubKey.Key = bz
	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey PubKey) MarshalAminoJSON() ([]byte, error) {
	return pubKey.MarshalAmino()
}

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey *PubKey) UnmarshalAminoJSON(bz []byte) error {
	return pubKey.UnmarshalAmino(bz)
}
