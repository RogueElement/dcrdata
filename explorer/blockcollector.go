// Copyright (c) 2017, The dcrdata developers
// See LICENSE for details.

package explorer

func (exp *explorerUI) blockDataCollector(newBlockHeightChan chan int64) {
	exp.collectBlock(int64(exp.blockData.GetHeight()))
	for {
		height, ok := <-newBlockHeightChan
		if !ok {
			log.Infof("New Tx channel closed")
			return
		}

		// -1 is the signal to stop
		if height == -1 {
			return
		}

		exp.collectBlock(height)
	}
}

func (exp *explorerUI) collectBlock(height int64) {
	exp.NewBlockDataMtx.Lock()
	block, hinfo := exp.blockData.GetExplorerHomeInfo(height)

	exp.NewBlockData = block

	devAddress := exp.ExtraInfo.DevAddress
	exp.ExtraInfo = hinfo
	exp.ExtraInfo.DevAddress = devAddress

	if !exp.liteMode {
		exp.ExtraInfo.DevFund = 0
		go exp.updateDevFundBalance()
	}

	exp.NewBlockDataMtx.Unlock()

	exp.wsHub.HubRelay <- sigNewBlock

	log.Debugf("Got new block %d for the explorer.", height)
}

func (exp *explorerUI) StartBlockCollector(newBlock chan int64) {
	go exp.blockDataCollector(newBlock)
}

func (exp *explorerUI) StopBlockCollector(newBlock chan int64) {
	log.Infof("Stopping block data collector")
	newBlock <- -1
}
