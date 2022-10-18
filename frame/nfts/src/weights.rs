// This file is part of Substrate.

// Copyright (C) 2022 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Autogenerated weights for pallet_nfts
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-10-03, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! HOSTNAME: `bm3`, CPU: `Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// /home/benchbot/cargo_target_dir/production/substrate
// benchmark
// pallet
// --steps=50
// --repeat=20
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --pallet=pallet_nfts
// --chain=dev
// --output=./frame/nfts/src/weights.rs
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_nfts.
pub trait WeightInfo {
	fn create() -> Weight;
	fn force_create() -> Weight;
	fn destroy(n: u32, m: u32, a: u32, ) -> Weight;
	fn mint() -> Weight;
	fn burn() -> Weight;
	fn transfer() -> Weight;
	fn redeposit(i: u32, ) -> Weight;
	fn lock_item_transfer() -> Weight;
	fn unlock_item_transfer() -> Weight;
	fn lock_collection() -> Weight;
	fn transfer_ownership() -> Weight;
	fn set_team() -> Weight;
	fn force_collection_status() -> Weight;
	fn lock_item_properties() -> Weight;
	fn set_attribute() -> Weight;
	fn clear_attribute() -> Weight;
	fn set_metadata() -> Weight;
	fn clear_metadata() -> Weight;
	fn set_collection_metadata() -> Weight;
	fn clear_collection_metadata() -> Weight;
	fn approve_transfer() -> Weight;
	fn cancel_approval() -> Weight;
	fn clear_all_transfer_approvals() -> Weight;
	fn set_accept_ownership() -> Weight;
	fn set_collection_max_supply() -> Weight;
	fn set_price() -> Weight;
	fn buy_item() -> Weight;
	fn pay_tips(n: u32, ) -> Weight;
	fn create_swap() -> Weight;
	fn cancel_swap() -> Weight;
	fn claim_swap() -> Weight;
}

/// Weights for pallet_nfts using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	// Storage: Nfts NextCollectionId (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn create() -> Weight {
		Weight::from_ref_time(38_062_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts NextCollectionId (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn force_create() -> Weight {
		Weight::from_ref_time(25_917_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:0)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts ClassMetadataOf (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	// Storage: Nfts CollectionMaxSupply (r:0 w:1)
	// Storage: Nfts Attribute (r:0 w:20)
	// Storage: Nfts InstanceMetadataOf (r:0 w:20)
	// Storage: Nfts ItemConfigOf (r:0 w:20)
	// Storage: Nfts Account (r:0 w:20)
	/// The range of component `n` is `[0, 1000]`.
	/// The range of component `m` is `[0, 1000]`.
	/// The range of component `a` is `[0, 1000]`.
	fn destroy(n: u32, m: u32, a: u32, ) -> Weight {
		Weight::from_ref_time(55_419_000 as u64)
			// Standard Error: 18_623
			.saturating_add(Weight::from_ref_time(12_843_237 as u64).saturating_mul(n as u64))
			// Standard Error: 27_329
			.saturating_add(Weight::from_ref_time(315_839 as u64).saturating_mul(m as u64))
			// Standard Error: 27_329
			.saturating_add(Weight::from_ref_time(217_497 as u64).saturating_mul(a as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().reads((1 as u64).saturating_mul(n as u64)))
			.saturating_add(T::DbWeight::get().writes(5 as u64))
			.saturating_add(T::DbWeight::get().writes((5 as u64).saturating_mul(n as u64)))
	}
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionMaxSupply (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:0 w:1)
	// Storage: Nfts Account (r:0 w:1)
	fn mint() -> Weight {
		Weight::from_ref_time(47_947_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:0 w:1)
	// Storage: Nfts Account (r:0 w:1)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn burn() -> Weight {
		Weight::from_ref_time(47_193_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(5 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts Account (r:0 w:2)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn transfer() -> Weight {
		Weight::from_ref_time(42_305_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts Asset (r:102 w:102)
	/// The range of component `i` is `[0, 5000]`.
	fn redeposit(i: u32, ) -> Weight {
		Weight::from_ref_time(26_327_000 as u64)
			// Standard Error: 10_090
			.saturating_add(Weight::from_ref_time(10_876_864 as u64).saturating_mul(i as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().reads((1 as u64).saturating_mul(i as u64)))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
			.saturating_add(T::DbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn lock_item_transfer() -> Weight {
		Weight::from_ref_time(28_194_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn unlock_item_transfer() -> Weight {
		Weight::from_ref_time(28_821_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:1)
	fn lock_collection() -> Weight {
		Weight::from_ref_time(25_896_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts OwnershipAcceptance (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:2)
	fn transfer_ownership() -> Weight {
		Weight::from_ref_time(32_728_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	fn set_team() -> Weight {
		Weight::from_ref_time(24_805_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn force_collection_status() -> Weight {
		Weight::from_ref_time(28_468_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(3 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn lock_item_properties() -> Weight {
		Weight::from_ref_time(27_377_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Attribute (r:1 w:1)
	fn set_attribute() -> Weight {
		Weight::from_ref_time(53_019_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Attribute (r:1 w:1)
	fn clear_attribute() -> Weight {
		Weight::from_ref_time(52_530_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts InstanceMetadataOf (r:1 w:1)
	fn set_metadata() -> Weight {
		Weight::from_ref_time(48_054_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts InstanceMetadataOf (r:1 w:1)
	fn clear_metadata() -> Weight {
		Weight::from_ref_time(46_590_000 as u64)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassMetadataOf (r:1 w:1)
	fn set_collection_metadata() -> Weight {
		Weight::from_ref_time(44_281_000 as u64)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ClassMetadataOf (r:1 w:1)
	fn clear_collection_metadata() -> Weight {
		Weight::from_ref_time(42_355_000 as u64)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	fn approve_transfer() -> Weight {
		Weight::from_ref_time(33_170_000 as u64)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	fn cancel_approval() -> Weight {
		Weight::from_ref_time(31_121_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	fn clear_all_transfer_approvals() -> Weight {
		Weight::from_ref_time(30_133_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts OwnershipAcceptance (r:1 w:1)
	fn set_accept_ownership() -> Weight {
		Weight::from_ref_time(26_421_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts CollectionMaxSupply (r:1 w:1)
	// Storage: Nfts Class (r:1 w:0)
	fn set_collection_max_supply() -> Weight {
		Weight::from_ref_time(26_358_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	fn set_price() -> Weight {
		Weight::from_ref_time(33_607_000 as u64)
			.saturating_add(T::DbWeight::get().reads(3 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts ItemPriceOf (r:1 w:1)
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Account (r:0 w:2)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn buy_item() -> Weight {
		Weight::from_ref_time(54_511_000 as u64)
			.saturating_add(T::DbWeight::get().reads(5 as u64))
			.saturating_add(T::DbWeight::get().writes(4 as u64))
	}
	/// The range of component `n` is `[0, 10]`.
	fn pay_tips(n: u32, ) -> Weight {
		Weight::from_ref_time(6_015_000 as u64)
			// Standard Error: 34_307
			.saturating_add(Weight::from_ref_time(4_308_600 as u64).saturating_mul(n as u64))
	}
	// Storage: Nfts Asset (r:2 w:0)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn create_swap() -> Weight {
		Weight::from_ref_time(30_330_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts PendingSwapOf (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:0)
	fn cancel_swap() -> Weight {
		Weight::from_ref_time(30_516_000 as u64)
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:2 w:2)
	// Storage: Nfts PendingSwapOf (r:1 w:2)
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Account (r:0 w:4)
	// Storage: Nfts ItemPriceOf (r:0 w:2)
	fn claim_swap() -> Weight {
		Weight::from_ref_time(66_191_000 as u64)
			.saturating_add(T::DbWeight::get().reads(4 as u64))
			.saturating_add(T::DbWeight::get().writes(10 as u64))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	// Storage: Nfts NextCollectionId (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn create() -> Weight {
		Weight::from_ref_time(39_252_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts NextCollectionId (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn force_create() -> Weight {
		Weight::from_ref_time(27_479_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:0)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts ClassMetadataOf (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	// Storage: Nfts CollectionMaxSupply (r:0 w:1)
	// Storage: Nfts Attribute (r:0 w:20)
	// Storage: Nfts InstanceMetadataOf (r:0 w:20)
	// Storage: Nfts ItemConfigOf (r:0 w:20)
	// Storage: Nfts Account (r:0 w:20)
	/// The range of component `n` is `[0, 1000]`.
	/// The range of component `m` is `[0, 1000]`.
	/// The range of component `a` is `[0, 1000]`.
	fn destroy(n: u32, m: u32, a: u32, ) -> Weight {
		Weight::from_ref_time(55_419_000 as u64)
			// Standard Error: 18_623
			.saturating_add(Weight::from_ref_time(12_843_237 as u64).saturating_mul(n as u64))
			// Standard Error: 27_329
			.saturating_add(Weight::from_ref_time(315_839 as u64).saturating_mul(m as u64))
			// Standard Error: 27_329
			.saturating_add(Weight::from_ref_time(217_497 as u64).saturating_mul(a as u64))
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(n as u64)))
			.saturating_add(RocksDbWeight::get().writes(5 as u64))
			.saturating_add(RocksDbWeight::get().writes((5 as u64).saturating_mul(n as u64)))
	}
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionMaxSupply (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:0 w:1)
	// Storage: Nfts Account (r:0 w:1)
	fn mint() -> Weight {
		Weight::from_ref_time(47_947_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:0 w:1)
	// Storage: Nfts Account (r:0 w:1)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn burn() -> Weight {
		Weight::from_ref_time(47_193_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(5 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts Account (r:0 w:2)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn transfer() -> Weight {
		Weight::from_ref_time(42_305_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts Asset (r:102 w:102)
	/// The range of component `i` is `[0, 5000]`.
	fn redeposit(i: u32, ) -> Weight {
		Weight::from_ref_time(26_327_000 as u64)
			// Standard Error: 10_090
			.saturating_add(Weight::from_ref_time(10_876_864 as u64).saturating_mul(i as u64))
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().reads((1 as u64).saturating_mul(i as u64)))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
			.saturating_add(RocksDbWeight::get().writes((1 as u64).saturating_mul(i as u64)))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn lock_item_transfer() -> Weight {
		Weight::from_ref_time(28_194_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn unlock_item_transfer() -> Weight {
		Weight::from_ref_time(28_821_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:1)
	fn lock_collection() -> Weight {
		Weight::from_ref_time(25_896_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts OwnershipAcceptance (r:1 w:1)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:2)
	fn transfer_ownership() -> Weight {
		Weight::from_ref_time(32_728_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	fn set_team() -> Weight {
		Weight::from_ref_time(24_805_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(1 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassAccount (r:0 w:1)
	// Storage: Nfts CollectionConfigOf (r:0 w:1)
	fn force_collection_status() -> Weight {
		Weight::from_ref_time(28_468_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(1 as u64))
			.saturating_add(RocksDbWeight::get().writes(3 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:1)
	fn lock_item_properties() -> Weight {
		Weight::from_ref_time(27_377_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Attribute (r:1 w:1)
	fn set_attribute() -> Weight {
		Weight::from_ref_time(53_019_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Attribute (r:1 w:1)
	fn clear_attribute() -> Weight {
		Weight::from_ref_time(52_530_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts InstanceMetadataOf (r:1 w:1)
	fn set_metadata() -> Weight {
		Weight::from_ref_time(48_054_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts InstanceMetadataOf (r:1 w:1)
	fn clear_metadata() -> Weight {
		Weight::from_ref_time(46_590_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts Class (r:1 w:1)
	// Storage: Nfts ClassMetadataOf (r:1 w:1)
	fn set_collection_metadata() -> Weight {
		Weight::from_ref_time(44_281_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(2 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ClassMetadataOf (r:1 w:1)
	fn clear_collection_metadata() -> Weight {
		Weight::from_ref_time(42_355_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	fn approve_transfer() -> Weight {
		Weight::from_ref_time(33_170_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	fn cancel_approval() -> Weight {
		Weight::from_ref_time(31_121_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Asset (r:1 w:1)
	fn clear_all_transfer_approvals() -> Weight {
		Weight::from_ref_time(30_133_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts OwnershipAcceptance (r:1 w:1)
	fn set_accept_ownership() -> Weight {
		Weight::from_ref_time(26_421_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(1 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts CollectionMaxSupply (r:1 w:1)
	// Storage: Nfts Class (r:1 w:0)
	fn set_collection_max_supply() -> Weight {
		Weight::from_ref_time(26_358_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts ItemPriceOf (r:0 w:1)
	fn set_price() -> Weight {
		Weight::from_ref_time(33_607_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(3 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:1 w:1)
	// Storage: Nfts ItemPriceOf (r:1 w:1)
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts CollectionConfigOf (r:1 w:0)
	// Storage: Nfts ItemConfigOf (r:1 w:0)
	// Storage: Nfts Account (r:0 w:2)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn buy_item() -> Weight {
		Weight::from_ref_time(54_511_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(5 as u64))
			.saturating_add(RocksDbWeight::get().writes(4 as u64))
	}
	/// The range of component `n` is `[0, 10]`.
	fn pay_tips(n: u32, ) -> Weight {
		Weight::from_ref_time(5_477_000 as u64)
			// Standard Error: 33_188
			.saturating_add(Weight::from_ref_time(4_285_339 as u64).saturating_mul(n as u64))
	}
	// Storage: Nfts Asset (r:2 w:0)
	// Storage: Nfts PendingSwapOf (r:0 w:1)
	fn create_swap() -> Weight {
		Weight::from_ref_time(30_330_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts PendingSwapOf (r:1 w:1)
	// Storage: Nfts Asset (r:1 w:0)
	fn cancel_swap() -> Weight {
		Weight::from_ref_time(30_516_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(2 as u64))
			.saturating_add(RocksDbWeight::get().writes(1 as u64))
	}
	// Storage: Nfts Asset (r:2 w:2)
	// Storage: Nfts PendingSwapOf (r:1 w:2)
	// Storage: Nfts Class (r:1 w:0)
	// Storage: Nfts Account (r:0 w:4)
	// Storage: Nfts ItemPriceOf (r:0 w:2)
	fn claim_swap() -> Weight {
		Weight::from_ref_time(66_191_000 as u64)
			.saturating_add(RocksDbWeight::get().reads(4 as u64))
			.saturating_add(RocksDbWeight::get().writes(10 as u64))
	}
}
