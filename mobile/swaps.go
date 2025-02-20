package lndmobile

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/BoltzExchange/boltz-client/boltz"
	"github.com/BoltzExchange/boltz-client/boltzrpc"
	"github.com/BoltzExchange/boltz-client/database"
	"github.com/BoltzExchange/boltz-client/lightning"
	"github.com/BoltzExchange/boltz-client/logger"
	"github.com/BoltzExchange/boltz-client/onchain"
	"github.com/BoltzExchange/boltz-client/utils"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Output struct {
	*boltz.OutputDetails
	walletId   *uint64
	outputArgs onchain.OutputArgs

	setTransaction func(transactionId string, fee uint64) error
	setError       func(err error)
}

// code from https://github.com/BoltzExchange/boltz-client/tree/master/internal/nursery

type SwapUpdate struct {
	Swap        *database.Swap
	ReverseSwap *database.ReverseSwap
	IsFinal     bool
}

type swapListener = *utils.ChannelForwarder[SwapUpdate]
type Nursery struct {
	ctx    context.Context
	cancel func()

	network *boltz.Network

	lightning lightning.LightningNode

	onchain  *onchain.Onchain
	boltz    *boltz.Api
	boltzWs  *boltz.Websocket
	database *database.Database

	eventListeners     map[string]swapListener
	eventListenersLock sync.RWMutex
	globalListener     swapListener
	waitGroup          sync.WaitGroup

	MaxZeroConfAmount uint64

	BtcBlocks    *utils.ChannelForwarder[*onchain.BlockEpoch]
	LiquidBlocks *utils.ChannelForwarder[*onchain.BlockEpoch]
}

func (nursery *Nursery) removeSwapListener(id string) {
	nursery.eventListenersLock.Lock()
	defer nursery.eventListenersLock.Unlock()
	if listener, ok := nursery.eventListeners[id]; ok {
		listener.Close()
		delete(nursery.eventListeners, id)
	}
}

func (nursery *Nursery) sendUpdate(id string, update SwapUpdate) {
	if update.IsFinal {
		nursery.boltzWs.Unsubscribe(id)
	}
	nursery.globalListener.Send(update)
	if listener, ok := nursery.eventListeners[id]; ok {
		listener.Send(update)
		logger.Debugf("Sent update for swap %s", id)

		if update.IsFinal {
			nursery.removeSwapListener(id)
		}
	} else {
		logger.Debugf("No listener for swap %s", id)
	}
}

func (nursery *Nursery) sendSwapUpdate(swap database.Swap) {
	isFinal := swap.State == boltzrpc.SwapState_SUCCESSFUL || swap.State == boltzrpc.SwapState_REFUNDED
	if swap.LockupTransactionId == "" && swap.State != boltzrpc.SwapState_PENDING {
		isFinal = false
	}

	nursery.sendUpdate(swap.Id, SwapUpdate{
		Swap:    &swap,
		IsFinal: isFinal,
	})
}

func (nursery *Nursery) handleSwapError(swap *database.Swap, err error) {
	if dbErr := nursery.database.UpdateSwapState(swap, boltzrpc.SwapState_ERROR, err.Error()); dbErr != nil {
		logger.Error(dbErr.Error())
	}
	logger.Errorf("Swap %s error: %v", swap.Id, err)
	nursery.sendSwapUpdate(*swap)
}

func swapOutputArgs(swap *database.Swap) onchain.OutputArgs {
	return onchain.OutputArgs{
		TransactionId: swap.LockupTransactionId,
		Currency:      swap.Pair.From,
		Address:       swap.Address,
		BlindingKey:   swap.BlindingKey,
	}
}

func leaf(script string) txscript.TapLeaf {
	decoded, _ := hex.DecodeString(script)
	return txscript.TapLeaf{
		LeafVersion: txscript.BaseLeafVersion,
		Script:      decoded,
	}
}

func (nursery *Nursery) getRefundOutput(Id string, RefundAddress string, PrivateKey string, TimoutBlockHeight uint32, claimLeaf string, refundLeaf string, walletId *uint64) *Output {
	// want (Id, RefundAddress, PrivateKey, TimoutBlockHeight, SwapTree)

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(PrivateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	return &Output{
		OutputDetails: &boltz.OutputDetails{
			SwapId:             Id,
			SwapType:           boltz.NormalSwap,
			Address:            RefundAddress,
			PrivateKey:         keys,
			Preimage:           []byte{},
			TimeoutBlockHeight: TimoutBlockHeight,
			SwapTree:           swapTree,
			Cooperative:        true,
		},
		walletId: walletId,
		// using swap object here but we dont have all those values with us yet
		outputArgs: swapOutputArgs(swap),
		setTransaction: func(transactionId string, fee uint64) error {
			if err := nursery.database.SetSwapRefundTransactionId(swap, transactionId, fee); err != nil {
				return err
			}

			nursery.sendSwapUpdate(*swap)

			return nil
		},
		setError: func(err error) {
			nursery.handleSwapError(swap, err)
		},
	}
}

func CreateClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, transactionHash string, pubNonce string) error {
	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return fmt.Errorf("Error decoding service public key hex: %s", err)
	}

	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("Error parsing service public key %s", err)
	}

	if err := swapTree.Init(false, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	session, err := boltz.NewSigningSession(swapTree)
	partial, err := session.Sign([]byte(transactionHash), []byte(pubNonce))
	if err != nil {
		return fmt.Errorf("could not create partial signature: %s", err)
	}

	boltzApi := &boltz.Api{URL: endpoint}
	if err := boltzApi.SendSwapClaimSignature(id, partial); err != nil {
		return fmt.Errorf("could not send partial signature to Boltz: %s", err)
	}

	return nil
}

func CreateReverseClaimTransaction(endpoint string, id string, claimLeaf string, refundLeaf string, privateKey string, servicePubKey string, preimageHex string, transactionHex string, lockupAddress string, destinationAddress string, feeRate int32, isTestnet bool) error {
	var toCurrency = boltz.CurrencyBtc
	var network *boltz.Network
	if isTestnet {
		network = boltz.TestNet
	} else {
		network = boltz.MainNet
	}

	boltzApi := &boltz.Api{URL: endpoint}

	// Decode the hex string to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		fmt.Printf("Failed to decode hex string: %v", err)
	}

	// Create the private key using btcec
	keys, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// Decode the hex string to bytes
	servicePubKeyBytes, err := hex.DecodeString(servicePubKey)
	if err != nil {
		return fmt.Errorf("Error decoding service public key hex: %s", err)
	}

	// Parse the public key
	servicePubKeyFormatted, err := secp256k1.ParsePubKey(servicePubKeyBytes)
	if err != nil {
		return fmt.Errorf("Error parsing service public key %s", err)
	}

	swapTree := &boltz.SwapTree{
		ClaimLeaf:  leaf(claimLeaf),
		RefundLeaf: leaf(refundLeaf),
	}

	if err := swapTree.Init(false, false, keys, servicePubKeyFormatted); err != nil {
		return fmt.Errorf("Error initializing swap tree %s", err)
	}

	lockupTransaction, err := boltz.NewTxFromHex(toCurrency, transactionHex, nil)
	if err != nil {
		return fmt.Errorf("Error constructing lockup tx %s", err)
	}

	vout, _, err := lockupTransaction.FindVout(network, lockupAddress)
	if err != nil {
		return fmt.Errorf("Error finding vout %s", err)
	}

	preimage, err := hex.DecodeString(preimageHex)
	if err != nil {
		return fmt.Errorf("Error decoding preimage hex string: %w", err)
	}

	satPerVbyte := float64(feeRate)
	claimTransaction, _, err := boltz.ConstructTransaction(
		network,
		boltz.CurrencyBtc,
		[]boltz.OutputDetails{
			{
				SwapId:            id,
				SwapType:          boltz.ReverseSwap,
				Address:           destinationAddress,
				LockupTransaction: lockupTransaction,
				Vout:              vout,
				Preimage:          preimage,
				PrivateKey:        keys,
				SwapTree:          swapTree,
				Cooperative:       true,
			},
		},
		satPerVbyte,
		boltzApi,
	)
	if err != nil {
		return fmt.Errorf("could not create claim transaction: %w", err)
	}

	txHex, err := claimTransaction.Serialize()
	if err != nil {
		return fmt.Errorf("could not serialize claim transaction: %w", err)
	}

	var broadcastUrl string
	if isTestnet {
		broadcastUrl = "https://mempool.space/testnet/api/tx"
	} else {
		broadcastUrl = "https://mempool.space/api/tx"
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", broadcastUrl, bytes.NewBufferString(txHex))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-200 response: %d, body: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Transaction broadcasted successfully: %s\n", string(body))

	return nil
}
