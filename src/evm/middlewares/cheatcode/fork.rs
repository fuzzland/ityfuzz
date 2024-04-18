use std::{cell::RefCell, rc::Rc, str::FromStr};

use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use foundry_cheatcodes::Vm;
use libafl::schedulers::Scheduler;

use super::Cheatcode;
use crate::evm::{
    config::StorageFetchingMode,
    host::FuzzHost,
    onchain::{
        endpoints::{Chain, OnChainConfig},
        OnChain,
    },
    types::EVMFuzzState,
};

/// Cheat VmCalls
impl<SC> Cheatcode<SC>
where
    SC: Scheduler<State = EVMFuzzState> + Clone,
{
    #[inline]
    pub fn create_select_fork0(&self, host: &mut FuzzHost<SC>, args: Vm::createSelectFork_0Call) -> Option<Vec<u8>> {
        let Vm::createSelectFork_0Call { urlOrAlias } = args;
        self.add_onchain_middleware(host, &urlOrAlias, None)
    }

    #[inline]
    pub fn create_select_fork1(&self, host: &mut FuzzHost<SC>, args: Vm::createSelectFork_1Call) -> Option<Vec<u8>> {
        let Vm::createSelectFork_1Call {
            urlOrAlias,
            blockNumber,
        } = args;
        self.add_onchain_middleware(host, &urlOrAlias, Some(blockNumber))
    }

    #[inline]
    pub fn create_select_fork2(&self, host: &mut FuzzHost<SC>, args: Vm::createSelectFork_2Call) -> Option<Vec<u8>> {
        // onchain middleware doesn't support txHash
        let Vm::createSelectFork_2Call { urlOrAlias, .. } = args;
        self.add_onchain_middleware(host, &urlOrAlias, None)
    }

    fn add_onchain_middleware(
        &self,
        host: &mut FuzzHost<SC>,
        url_or_alias: &str,
        block: Option<U256>,
    ) -> Option<Vec<u8>> {
        let chain = if url_or_alias.starts_with("http") {
            Chain::new_with_rpc_url(url_or_alias).ok()?
        } else {
            Chain::from_str(url_or_alias).ok()?
        };
        let block_number = block.map(|b| b.as_limbs()[0]).unwrap_or_default();
        let mut onchain = OnChainConfig::new(chain, block_number);
        onchain.etherscan_api_key = self.etherscan_api_key.clone();

        let storage_fetching = StorageFetchingMode::OneByOne;
        tracing::debug!("createSelectFork(\"{url_or_alias}\", {block_number}), {onchain:?})");

        let mid = Rc::new(RefCell::new(OnChain::new(onchain, storage_fetching)));
        host.add_middlewares(mid);

        Some(U256::ZERO.abi_encode())
    }
}
