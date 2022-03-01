package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	bls_core "github.com/harmony-one/bls/ffi/go/bls"
	"github.com/harmony-one/harmony/block"
	"github.com/harmony-one/harmony/consensus/quorum"
	"github.com/harmony-one/harmony/crypto/bls"
	"github.com/harmony-one/harmony/shard"
)

var (
	// Harmony staking epoch
	stakingEpoch uint64 = 186
)

type Epoch struct {
	EpochID     uint64
	Committee   *shard.Committee
	StartHeight uint64
	EndHeight   uint64 //TODO determin the last block of epoch
}

type HeaderWithSigs struct {
	Header *block.Header
	Sig    hexutil.Bytes
	Bitmap hexutil.Bytes
}

func (hs *HeaderWithSigs) ExtractEpoch() (epoch *Epoch, err error) {
	shardStateBytes := hs.Header.ShardState()
	if len(shardStateBytes) == 0 {
		err = fmt.Errorf("Unexpected empty shard state")
		return
	}
	shardState, err := shard.DecodeWrapper(shardStateBytes)
	if err != nil {
		return
	}
	if shardState == nil {
		return nil, fmt.Errorf("Unexpected decoded empty shardState")
	}
	committee, err := shardState.FindCommitteeByID(hs.Header.ShardID())
	if err != nil {
		return
	}
	epoch = &Epoch{
		EpochID:     hs.Header.Epoch().Uint64(),
		Committee:   committee,
		StartHeight: hs.Header.Number().Uint64(),
	}
	return
}

type Handler struct {
	chainID int
	shardID uint32
	epoch   *Epoch
}

// Parse genesis header, decode committee, verify header with signatures
func (h *Handler) SyncGenesisHeader(chainID int, genesis []byte) (err error) {
	if chainID == 0 || h.chainID != 0 {
		return fmt.Errorf("Invalid chain id %v cur %v", chainID, h.chainID)
	}
	header := new(HeaderWithSigs)
	err = json.Unmarshal(genesis, header)
	if err != nil {
		return
	}

	err = verifyHeader(header.Header)
	if err != nil {
		return
	}

	// Storage mock
	h.chainID = chainID
	h.shardID = header.Header.ShardID()
	h.epoch, err = header.ExtractEpoch()
	return
}

func (h *Handler) SyncBlockHeader(data [][]byte) (err error) {
	if len(data) == 0 {
		return fmt.Errorf("Empty header")
	}
	for _, headerBytes := range data {
		header := new(HeaderWithSigs)
		err = json.Unmarshal(headerBytes, header)
		if err != nil {
			return
		}
		err = verifyHeader(header.Header)
		if err != nil {
			return
		}
		err = verifyHeaderSigs(h.epoch, header)
		if err != nil {
			return
		}
		err = h.VerifyHeaderFields(header.Header)
		if err != nil {
			return
		}
		epoch, err := header.ExtractEpoch()
		if err != nil {
			return err
		}
		// ensure epoch is consistent
		if epoch.EpochID != h.epoch.EpochID+1 {
			return fmt.Errorf("Invalid new epoch ID %v cur %v", epoch.EpochID, h.epoch.EpochID)
		}
		// storage epoch
		h.epoch = epoch
		fmt.Printf("New epoch verified %v", epoch.EpochID)
	}
	return
}

// Check shard, epoch, height
func (h *Handler) VerifyHeaderFields(header *block.Header) (err error) {
	if header.ShardID() != h.shardID {
		return fmt.Errorf("Invalid header shard %v expect %v", header.ShardID(), h.shardID)
	}
	if header.Epoch().Uint64() != h.epoch.EpochID {
		return fmt.Errorf("Invalid header epoch %v expect %v", header.Epoch(), h.epoch.EpochID)
	}
	height := header.Number().Uint64()
	if height < h.epoch.StartHeight || height > h.epoch.EndHeight {
		return fmt.Errorf("Invalid header height %v expect range: %v to %v", height, h.epoch.StartHeight, h.epoch.EndHeight)
	}
	return
}

// Verify header
func verifyHeader(header *block.Header) (err error) {
	return
}

func verifyHeaderSigs(epoch *Epoch, header *HeaderWithSigs) (err error) {
	pubKeys, err := epoch.Committee.BLSPublicKeys()
	if err != nil {
		return
	}

	sigBytes := bls.SerializedSignature{}
	copy(sigBytes[:], header.Sig)
	aggSig, mask, err := DecodeSigBitmap(sigBytes, []byte(header.Bitmap), pubKeys)
	if err != nil {
		return
	}

	isStaking := epoch.EpochID >= stakingEpoch
	qrVerifier, err := quorum.NewVerifier(epoch.Committee, big.NewInt(int64(epoch.EpochID)), isStaking)
	if err != nil {
		return
	}
	if !qrVerifier.IsQuorumAchievedByMask(mask) {
		return errors.New("not enough signature collected")
	}

	commitPayload := ConstructCommitPayload(
		isStaking, header.Header.Hash(), header.Header.Number().Uint64(), header.Header.ViewID().Uint64(),
	)
	if !aggSig.VerifyHash(mask.AggregatePublic, commitPayload) {
		return errors.New("Unable to verify aggregated signature for block")
	}

	return
}

// DecodeSigBitmap decode and parse the signature, bitmap with the given public keys
func DecodeSigBitmap(sigBytes bls.SerializedSignature, bitmap []byte, pubKeys []bls.PublicKeyWrapper) (*bls_core.Sign, *bls.Mask, error) {
	aggSig := bls_core.Sign{}
	err := aggSig.Deserialize(sigBytes[:])
	if err != nil {
		return nil, nil, errors.New("unable to deserialize multi-signature from payload")
	}
	mask, err := bls.NewMask(pubKeys, nil)
	if err != nil {
		return nil, nil, errors.New("unable to setup mask from payload")
	}
	if err := mask.SetMask(bitmap); err != nil {
		return nil, nil, errors.New("mask.SetMask failed")
	}
	return &aggSig, mask, nil
}

// ConstructCommitPayload returns the commit payload for consensus signatures.
func ConstructCommitPayload(
	isStaking bool, blockHash common.Hash, blockNum, viewID uint64,
) []byte {
	blockNumBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(blockNumBytes, blockNum)
	commitPayload := append(blockNumBytes, blockHash.Bytes()...)
	if !isStaking {
		return commitPayload
	}
	viewIDBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(viewIDBytes, viewID)
	return append(commitPayload, viewIDBytes...)
}
