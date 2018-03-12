// Copyright (c) 2017, The dcrdata developers
// See LICENSE for details.

package explorer

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/decred/dcrd/blockchain/stake"
	"github.com/decred/dcrd/chaincfg"
	"github.com/decred/dcrd/chaincfg/chainhash"
	"github.com/decred/dcrd/dcrjson"
	"github.com/decred/dcrd/dcrutil"
	"github.com/decred/dcrd/rpcclient"
	"github.com/decred/dcrd/wire"
	"github.com/decred/dcrdata/rpcutils"
	"github.com/decred/dcrdata/txhelpers"
	humanize "github.com/dustin/go-humanize"
)

type RpcDB struct {
	params *chaincfg.Params
	client *rpcclient.Client
}

func NewRpc(params *chaincfg.Params, client *rpcclient.Client) RpcDB {
	return RpcDB{
		params: params,
		client: client,
	}
}

func (db RpcDB) GetBlockVerbose(idx int, verboseTx bool) *dcrjson.GetBlockVerboseResult {
	return rpcutils.GetBlockVerbose(db.client, db.params, int64(idx), verboseTx)
}

func (db RpcDB) GetBlockVerboseByHash(hash string, verboseTx bool) *dcrjson.GetBlockVerboseResult {
	return rpcutils.GetBlockVerboseByHash(db.client, db.params, hash, verboseTx)
}

func (db RpcDB) GetBlockHash(idx int64) (string, error) {
	hash, err := db.client.GetBlockHash(idx)
	if err != nil {
		log.Errorf("Unable to get block hash for block number %d: %v", idx, err)
		return "", err
	}
	return hash.String(), nil
}

func (db RpcDB) GetHeight() int {
	_, height, err := db.client.GetBestBlock()
	if err != nil {
		log.Errorf("Unable to get best block: %v", err)
		return -1
	}
	return int(height)
}

func (db RpcDB) GetChainParams() *chaincfg.Params {
	return db.params
}

func (db RpcDB) DecodeRawTransaction(txhex string) (*dcrjson.TxRawResult, error) {
	bytes, err := hex.DecodeString(txhex)
	if err != nil {
		log.Errorf("DecodeRawTransaction failed: %v", err)
		return nil, err
	}
	tx, err := db.client.DecodeRawTransaction(bytes)
	if err != nil {
		log.Errorf("DecodeRawTransaction failed: %v", err)
		return nil, err
	}
	return tx, nil
}

func (db RpcDB) SendRawTransaction(txhex string) (string, error) {
	msg, err := txhelpers.MsgTxFromHex(txhex)
	if err != nil {
		log.Errorf("SendRawTransaction failed: could not decode tx")
		return "", err
	}
	hash, err := db.client.SendRawTransaction(msg, true)
	if err != nil {
		log.Errorf("SendRawTransaction failed: %v", err)
		return "", err
	}
	return hash.String(), err
}

func (db RpcDB) GetBlockHeight(hash string) (int64, error) {
	_, height, err := db.client.GetBestBlock()
	if err != nil {
		log.Errorf("Unable to get block height for hash %s: %v", hash, err)
		return -1, err
	}
	return height, nil
}

func (db RpcDB) GetBestBlockHeight() int64 {
	_, h, err := db.client.GetBestBlock()
	if err != nil {
		return 0
	}
	return h
}

func (db RpcDB) getRawTransaction(txid string) *dcrjson.TxRawResult {

	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		log.Errorf("Invalid transaction hash %s", txid)
		return nil
	}

	txraw, err := db.client.GetRawTransactionVerbose(txhash)
	if err != nil {
		log.Errorf("GetRawTransactionVerbose failed for: %v", txhash)
		return nil
	}

	return txraw
}

func makeExplorerBlockBasic(data *dcrjson.GetBlockVerboseResult) *BlockBasic {
	block := &BlockBasic{
		Height:         data.Height,
		Size:           data.Size,
		Valid:          true, // we do not know this, TODO with DB v2
		Voters:         data.Voters,
		Transactions:   len(data.RawTx),
		FreshStake:     data.FreshStake,
		BlockTime:      data.Time,
		FormattedBytes: humanize.Bytes(uint64(data.Size)),
		FormattedTime:  time.Unix(data.Time, 0).Format("2006-01-02 15:04:05"),
	}

	// Count the number of revocations
	for i := range data.RawSTx {
		msgTx, err := txhelpers.MsgTxFromHex(data.RawSTx[i].Hex)
		if err != nil {
			log.Errorf("Unknown transaction %s", data.RawSTx[i].Txid)
			continue
		}
		if stake.IsSSRtx(msgTx) {
			block.Revocations++
		}
	}
	return block
}

func makeExplorerTxBasic(data dcrjson.TxRawResult, msgTx *wire.MsgTx, params *chaincfg.Params) *TxBasic {
	tx := new(TxBasic)
	tx.TxID = data.Txid
	tx.FormattedSize = humanize.Bytes(uint64(len(data.Hex) / 2))
	tx.Total = txhelpers.TotalVout(data.Vout).ToCoin()
	tx.Fee, tx.FeeRate = txhelpers.TxFeeRate(msgTx)
	for _, i := range data.Vin {
		if i.IsCoinBase() {
			tx.Coinbase = true
		}
	}
	if stake.IsSSGen(msgTx) {
		validation, version, bits, choices, err := txhelpers.SSGenVoteChoices(msgTx, params)
		if err != nil {
			log.Debugf("Cannot get vote choices for %s", tx.TxID)
			return tx
		}
		tx.VoteInfo = &VoteInfo{
			Validation: BlockValidation{
				Hash:     validation.Hash.String(),
				Height:   validation.Height,
				Validity: validation.Validity,
			},
			Version: version,
			Bits:    bits,
			Choices: choices,
		}
	}
	return tx
}

func makeExplorerAddressTx(data *dcrjson.SearchRawTransactionsResult, address string) *AddressTx {
	tx := new(AddressTx)
	tx.TxID = data.Txid
	tx.FormattedSize = humanize.Bytes(uint64(len(data.Hex) / 2))
	tx.Total = txhelpers.TotalVout(data.Vout).ToCoin()
	tx.Time = data.Time
	t := time.Unix(tx.Time, 0)
	tx.FormattedTime = t.Format("2006-01-02 15:04:05")
	tx.Confirmations = data.Confirmations

	for i := range data.Vin {
		if data.Vin[i].PrevOut != nil && len(data.Vin[i].PrevOut.Addresses) > 0 {
			if data.Vin[i].PrevOut.Addresses[0] == address {
				tx.SentTotal += *data.Vin[i].AmountIn
			}
		}
	}
	for i := range data.Vout {
		if len(data.Vout[i].ScriptPubKey.Addresses) != 0 {
			if data.Vout[i].ScriptPubKey.Addresses[0] == address {
				tx.RecievedTotal += data.Vout[i].Value
			}
		}
	}
	return tx
}

func (db RpcDB) GetExplorerBlocks(start int, end int) []*BlockBasic {
	if start < end {
		return nil
	}
	summaries := make([]*BlockBasic, 0, start-end)
	for i := start; i > end; i-- {
		data := db.GetBlockVerbose(i, true)
		block := new(BlockBasic)
		if data != nil {
			block = makeExplorerBlockBasic(data)
		}
		summaries = append(summaries, block)
	}
	return summaries
}

func (db RpcDB) GetExplorerHomeInfo(height int64) (*BlockBasic, *HomeInfo) {
	data := db.GetBlockVerbose(int(height), true)
	block := new(BlockBasic)
	if data != nil {
		block = makeExplorerBlockBasic(data)
	}

	coinSupply, err := db.client.GetCoinSupply()
	if err != nil {
		log.Error("GetCoinSupply failed: ", err)
	}
	blockSubsidy, err := db.client.GetBlockSubsidy(int64(height)+1, 5)
	if err != nil {
		log.Errorf("GetBlockSubsidy for %d failed: %v", height, err)
	}

	poolSize := data.PoolSize

	poolValue, err := db.client.GetTicketPoolValue()

	poolVal := poolValue.ToCoin()

	percentage := func(a float64, b float64) float64 {
		return (a / b) * 100
	}

	hinfo := &HomeInfo{
		CoinSupply:        int64(coinSupply),
		StakeDiff:         data.SBits,
		IdxBlockInWindow:  int(height%db.params.StakeDiffWindowSize) + 1,
		IdxInRewardWindow: int(height % db.params.SubsidyReductionInterval),
		Difficulty:        data.Difficulty,
		NBlockSubsidy: BlockSubsidy{
			Dev:   blockSubsidy.Developer,
			PoS:   blockSubsidy.PoS,
			PoW:   blockSubsidy.PoW,
			Total: blockSubsidy.Total,
		},
		Params: ChainParams{
			WindowSize:       db.params.StakeDiffWindowSize,
			RewardWindowSize: db.params.SubsidyReductionInterval,
			BlockTime:        db.params.TargetTimePerBlock.Nanoseconds(),
		},
		PoolInfo: TicketPoolInfo{
			Size:       poolSize,
			Value:      poolVal,
			Percentage: percentage(poolVal, dcrutil.Amount(coinSupply).ToCoin()),
			Target:     db.params.TicketPoolSize * db.params.TicketsPerBlock,
			PercentTarget: func() float64 {
				target := float64(db.params.TicketPoolSize * db.params.TicketsPerBlock)
				return float64(poolSize) / target * 100
			}(),
		},
		TicketROI: percentage(dcrutil.Amount(blockSubsidy.PoS).ToCoin()/5, data.Difficulty),
		ROIPeriod: fmt.Sprintf("%.2f days", db.params.TargetTimePerBlock.Seconds()*float64(db.params.TicketPoolSize)/86400),
	}
	return block, hinfo
}

func (db RpcDB) GetExplorerBlock(hash string) *BlockInfo {
	data := db.GetBlockVerboseByHash(hash, true)
	if data == nil {
		log.Error("Unable to get block for block hash " + hash)
		return nil
	}

	// Explorer Block Info
	block := &BlockInfo{
		BlockBasic:            makeExplorerBlockBasic(data),
		Hash:                  data.Hash,
		Version:               data.Version,
		Confirmations:         data.Confirmations,
		StakeRoot:             data.StakeRoot,
		MerkleRoot:            data.MerkleRoot,
		Nonce:                 data.Nonce,
		VoteBits:              data.VoteBits,
		FinalState:            data.FinalState,
		PoolSize:              data.PoolSize,
		Bits:                  data.Bits,
		SBits:                 data.SBits,
		Difficulty:            data.Difficulty,
		ExtraData:             data.ExtraData,
		StakeVersion:          data.StakeVersion,
		PreviousHash:          data.PreviousHash,
		NextHash:              data.NextHash,
		StakeValidationHeight: db.params.StakeValidationHeight,
	}

	votes := make([]*TxBasic, 0, block.Voters)
	revocations := make([]*TxBasic, 0, block.Revocations)
	tickets := make([]*TxBasic, 0, block.FreshStake)

	for _, tx := range data.RawSTx {
		msgTx, err := txhelpers.MsgTxFromHex(tx.Hex)
		if err != nil {
			log.Errorf("Unknown transaction %s: %v", tx.Txid, err)
			return nil
		}
		switch stake.DetermineTxType(msgTx) {
		case stake.TxTypeSSGen:
			stx := makeExplorerTxBasic(tx, msgTx, db.params)
			stx.Fee, stx.FeeRate = 0.0, 0.0
			votes = append(votes, stx)
		case stake.TxTypeSStx:
			stx := makeExplorerTxBasic(tx, msgTx, db.params)
			tickets = append(tickets, stx)
		case stake.TxTypeSSRtx:
			stx := makeExplorerTxBasic(tx, msgTx, db.params)
			revocations = append(revocations, stx)
		}
	}

	txs := make([]*TxBasic, 0, block.Transactions)
	for _, tx := range data.RawTx {
		msgTx, err := txhelpers.MsgTxFromHex(tx.Hex)
		if err != nil {
			continue
		}
		exptx := makeExplorerTxBasic(tx, msgTx, db.params)
		for _, vin := range tx.Vin {
			if vin.IsCoinBase() {
				exptx.Fee, exptx.FeeRate = 0.0, 0.0
			}
		}
		txs = append(txs, exptx)
	}
	block.Tx = txs
	block.Votes = votes
	block.Revs = revocations
	block.Tickets = tickets

	sortTx := func(txs []*TxBasic) {
		sort.Slice(txs, func(i, j int) bool {
			return txs[i].Total > txs[j].Total
		})
	}

	sortTx(block.Tx)
	sortTx(block.Votes)
	sortTx(block.Revs)
	sortTx(block.Tickets)

	getTotalFee := func(txs []*TxBasic) (total dcrutil.Amount) {
		for _, tx := range txs {
			total += tx.Fee
		}
		return
	}
	getTotalSent := func(txs []*TxBasic) (total dcrutil.Amount) {
		for _, tx := range txs {
			amt, err := dcrutil.NewAmount(tx.Total)
			if err != nil {
				continue
			}
			total += amt
		}
		return
	}
	block.TotalSent = (getTotalSent(block.Tx) + getTotalSent(block.Revs) +
		getTotalSent(block.Tickets) + getTotalSent(block.Votes)).ToCoin()
	block.MiningFee = getTotalFee(block.Tx) + getTotalFee(block.Revs) +
		getTotalFee(block.Tickets)

	return block
}

func (db RpcDB) GetExplorerTx(txid string) *TxInfo {
	txhash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		log.Errorf("Invalid transaction hash %s", txid)
		return nil
	}
	txraw, err := db.client.GetRawTransactionVerbose(txhash)
	if err != nil {
		log.Errorf("GetRawTransactionVerbose failed for: %v", txhash)
		return nil
	}
	msgTx, err := txhelpers.MsgTxFromHex(txraw.Hex)
	if err != nil {
		log.Errorf("Cannot create MsgTx for tx %v: %v", txhash, err)
		return nil
	}
	txBasic := makeExplorerTxBasic(*txraw, msgTx, db.params)
	tx := &TxInfo{
		TxBasic: txBasic,
	}
	tx.Type = txhelpers.DetermineTxTypeString(msgTx)
	tx.BlockHeight = txraw.BlockHeight
	tx.BlockIndex = txraw.BlockIndex
	tx.Confirmations = txraw.Confirmations
	tx.Time = txraw.Time
	t := time.Unix(tx.Time, 0)
	tx.FormattedTime = t.Format("2006-01-02 15:04:05")

	inputs := make([]Vin, 0, len(txraw.Vin))
	for i, vin := range txraw.Vin {
		var addresses []string
		if !(vin.IsCoinBase() || (vin.IsStakeBase() && i == 0)) {
			addrs, err := txhelpers.OutPointAddresses(&msgTx.TxIn[i].PreviousOutPoint, db.client, db.params)
			if err != nil {
				log.Warnf("Failed to get outpoint address from txid: %v", err)
				continue
			}
			addresses = addrs
		}
		inputs = append(inputs, Vin{
			Vin: &dcrjson.Vin{
				Txid:        vin.Txid,
				Coinbase:    vin.Coinbase,
				Stakebase:   vin.Stakebase,
				Vout:        vin.Vout,
				AmountIn:    vin.AmountIn,
				BlockHeight: vin.BlockHeight,
			},
			Addresses:       addresses,
			FormattedAmount: humanize.Commaf(vin.AmountIn),
		})
	}
	tx.Vin = inputs
	if tx.Vin[0].IsCoinBase() {
		tx.Type = "Coinbase"
	}
	if tx.Type == "Coinbase" {
		if tx.Confirmations < int64(db.params.CoinbaseMaturity) {
			tx.Mature = "False"
		} else {
			tx.Mature = "True"
		}
	}
	if tx.Type == "Vote" || tx.Type == "Ticket" {
		if db.GetBestBlockHeight() >= (int64(db.params.TicketMaturity) + tx.BlockHeight) {
			tx.Mature = "True"
		} else {
			tx.Mature = "False"
			tx.TicketInfo.TicketMaturity = int64(db.params.TicketMaturity)
		}
	}
	if tx.Type == "Vote" {
		if tx.Confirmations < int64(db.params.CoinbaseMaturity) {
			tx.VoteFundsLocked = "True"
		} else {
			tx.VoteFundsLocked = "False"
		}
	}
	outputs := make([]Vout, 0, len(txraw.Vout))
	for i, vout := range txraw.Vout {
		txout, err := db.client.GetTxOut(txhash, uint32(i), true)
		if err != nil {
			log.Warnf("Failed to determine if tx out is spent for output %d of tx %s", i, txid)
		}
		var opReturn string
		if strings.Contains(vout.ScriptPubKey.Asm, "OP_RETURN") {
			opReturn = vout.ScriptPubKey.Asm
		}
		outputs = append(outputs, Vout{
			Addresses:       vout.ScriptPubKey.Addresses,
			Amount:          vout.Value,
			FormattedAmount: humanize.Commaf(vout.Value),
			OP_RETURN:       opReturn,
			Type:            vout.ScriptPubKey.Type,
			Spent:           txout == nil,
		})
	}
	tx.Vout = outputs

	// Initialize the spending transaction slice for safety
	tx.SpendingTxns = make([]TxInID, len(outputs))

	return tx
}

func (db RpcDB) GetExplorerAddress(address string, count, offset int64) *AddressInfo {
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		log.Infof("Invalid address %s: %v", address, err)
		return nil
	}

	maxcount := MaxAddressRows
	txs, err := db.client.SearchRawTransactionsVerbose(addr,
		int(offset), int(maxcount), true, true, nil)
	if err != nil && err.Error() == "-32603: No Txns available" {
		log.Warnf("GetAddressTransactionsRaw failed for address %s: %v", addr, err)

		if !ValidateNetworkAddress(addr, db.params) {
			log.Warnf("Address %s is not valid for this network", address)
			return nil
		}
		return &AddressInfo{
			Address:    address,
			MaxTxLimit: maxcount,
		}
	} else if err != nil {
		log.Warnf("GetAddressTransactionsRaw failed for address %s: %v", addr, err)
		return nil
	}

	addressTxs := make([]*AddressTx, 0, len(txs))
	for i, tx := range txs {
		if int64(i) == count {
			break
		}
		addressTxs = append(addressTxs, makeExplorerAddressTx(tx, address))
	}

	var numUnconfirmed, numReceiving, numSpending int64
	var totalreceived, totalsent dcrutil.Amount

	for _, tx := range txs {
		if tx.Confirmations == 0 {
			numUnconfirmed++
		}
		for _, y := range tx.Vout {
			if len(y.ScriptPubKey.Addresses) != 0 {
				if address == y.ScriptPubKey.Addresses[0] {
					t, _ := dcrutil.NewAmount(y.Value)
					if t > 0 {
						totalreceived += t
					}
					numReceiving++
				}
			}
		}
		for _, u := range tx.Vin {
			if u.PrevOut != nil && len(u.PrevOut.Addresses) != 0 {
				if address == u.PrevOut.Addresses[0] {
					t, _ := dcrutil.NewAmount(*u.AmountIn)
					if t > 0 {
						totalsent += t
					}
					numSpending++
				}
			}
		}
	}
	numberMaxOfTx := int64(len(txs))
	var numTxns = count
	if numberMaxOfTx < count {
		numTxns = numberMaxOfTx
	}
	balance := &AddressBalance{
		Address:      address,
		NumSpent:     numSpending,
		NumUnspent:   numReceiving,
		TotalSpent:   int64(totalsent),
		TotalUnspent: int64(totalreceived - totalsent),
	}
	return &AddressInfo{
		Address:           address,
		Limit:             count,
		MaxTxLimit:        maxcount,
		Offset:            offset,
		Transactions:      addressTxs,
		NumTransactions:   numTxns,
		KnownTransactions: numberMaxOfTx,
		KnownFundingTxns:  numReceiving,
		NumSpendingTxns:   numSpending,
		NumUnconfirmed:    numUnconfirmed,
		TotalReceived:     totalreceived,
		TotalSent:         totalsent,
		Unspent:           totalreceived - totalsent,
		Balance:           balance,
	}
}

func ValidateNetworkAddress(address dcrutil.Address, p *chaincfg.Params) bool {
	return address.IsForNet(p)
}

// CountUnconfirmedTransactions returns the number of unconfirmed transactions involving the specified address,
// given a maximum possible unconfirmed
func (db RpcDB) CountUnconfirmedTransactions(address string, maxUnconfirmedPossible int64) (numUnconfirmed int64, err error) {
	addr, err := dcrutil.DecodeAddress(address)
	if err != nil {
		log.Infof("Invalid address %s: %v", address, err)
		return
	}
	txs, err := db.client.SearchRawTransactionsVerbose(addr, 0, int(maxUnconfirmedPossible), true, true, nil)
	if err != nil {
		log.Warnf("GetAddressTransactionsRaw failed for address %s: %v", addr, err)
		return
	}
	for _, tx := range txs {
		if tx.Confirmations == 0 {
			numUnconfirmed++
		}
	}
	return
}

// GetMepool gets all transactions from the mempool for explorer
// and adds the total out for all the txs and vote info for the votes
func (db RpcDB) GetMempool() []MempoolTx {
	mempooltxs, err := db.client.GetRawMempoolVerbose(dcrjson.GRMAll)
	if err != nil {
		return nil
	}

	txs := make([]MempoolTx, 0, len(mempooltxs))

	for hash, tx := range mempooltxs {
		rawtx := db.getRawTransaction(hash)
		total := 0.0
		if rawtx == nil {
			continue
		}
		for _, v := range rawtx.Vout {
			total += v.Value
		}
		msgTx, err := txhelpers.MsgTxFromHex(rawtx.Hex)
		if err != nil {
			continue
		}
		var voteInfo *VoteInfo

		if ok := stake.IsSSGen(msgTx); ok {
			validation, version, bits, choices, err := txhelpers.SSGenVoteChoices(msgTx, db.params)
			if err != nil {
				log.Debugf("Cannot get vote choices for %s", hash)

			} else {
				voteInfo = &VoteInfo{
					Validation: BlockValidation{
						Hash:     validation.Hash.String(),
						Height:   validation.Height,
						Validity: validation.Validity,
					},
					Version: version,
					Bits:    bits,
					Choices: choices,
				}
			}
		}
		txs = append(txs, MempoolTx{
			Hash:     hash,
			Time:     tx.Time,
			Size:     tx.Size,
			TotalOut: total,
			Type:     txhelpers.DetermineTxTypeString(msgTx),
			VoteInfo: voteInfo,
		})
	}

	return txs
}
