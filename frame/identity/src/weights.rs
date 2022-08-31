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

//! Autogenerated weights for pallet_identity
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-06-03, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dev"), DB CACHE: 1024

// Executed Command:
// target/production/substrate
// benchmark
// pallet
// --chain=dev
// --steps=50
// --repeat=20
// --pallet=pallet_identity
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=./frame/identity/src/weights.rs
// --template=./.maintain/frame-weight-template.hbs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{RefTimeWeight, Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_identity.
pub trait WeightInfo {
	fn add_registrar(r: u32, ) -> Weight;
	fn set_identity(r: u32, x: u32, ) -> Weight;
	fn set_subs_new(s: u32, ) -> Weight;
	fn set_subs_old(p: u32, ) -> Weight;
	fn clear_identity(r: u32, s: u32, x: u32, ) -> Weight;
	fn request_judgement(r: u32, x: u32, ) -> Weight;
	fn cancel_request(r: u32, x: u32, ) -> Weight;
	fn set_fee(r: u32, ) -> Weight;
	fn set_account_id(r: u32, ) -> Weight;
	fn set_fields(r: u32, ) -> Weight;
	fn provide_judgement(r: u32, x: u32, ) -> Weight;
	fn kill_identity(r: u32, s: u32, x: u32, ) -> Weight;
	fn add_sub(s: u32, ) -> Weight;
	fn rename_sub(s: u32, ) -> Weight;
	fn remove_sub(s: u32, ) -> Weight;
	fn quit_sub(s: u32, ) -> Weight;
}

/// Weights for pallet_identity using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn add_registrar(r: u32, ) -> Weight {
		Weight::from_ref_time(16_649_000 as RefTimeWeight)
			// Standard Error: 5_000
			.saturating_add(Weight::from_ref_time(241_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn set_identity(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(31_322_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(252_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(312_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity SuperOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn set_subs_new(s: u32, ) -> Weight {
		Weight::from_ref_time(30_012_000 as RefTimeWeight)
			// Standard Error: 2_000
			.saturating_add(Weight::from_ref_time(3_005_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:1)
	/// The range of component `p` is `[1, 100]`.
	fn set_subs_old(p: u32, ) -> Weight {
		Weight::from_ref_time(29_623_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_100_000 as RefTimeWeight).scalar_saturating_mul(p as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes((1 as RefTimeWeight).saturating_mul(p as RefTimeWeight)))
	}
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity IdentityOf (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:100)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `s` is `[1, 100]`.
	/// The range of component `x` is `[1, 100]`.
	fn clear_identity(r: u32, s: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(34_370_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(186_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_114_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(189_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity Registrars (r:1 w:0)
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn request_judgement(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(34_759_000 as RefTimeWeight)
			// Standard Error: 4_000
			.saturating_add(Weight::from_ref_time(251_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(340_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn cancel_request(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(32_254_000 as RefTimeWeight)
			// Standard Error: 7_000
			.saturating_add(Weight::from_ref_time(159_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(347_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_fee(r: u32, ) -> Weight {
		Weight::from_ref_time(7_858_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(190_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_account_id(r: u32, ) -> Weight {
		Weight::from_ref_time(8_011_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(187_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_fields(r: u32, ) -> Weight {
		Weight::from_ref_time(7_970_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(175_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:0)
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	/// The range of component `x` is `[1, 100]`.
	fn provide_judgement(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(24_730_000 as RefTimeWeight)
			// Standard Error: 4_000
			.saturating_add(Weight::from_ref_time(196_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(341_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity IdentityOf (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:100)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `s` is `[1, 100]`.
	/// The range of component `x` is `[1, 100]`.
	fn kill_identity(r: u32, s: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(44_988_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(201_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_126_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(2_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(3 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 99]`.
	fn add_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(36_768_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(115_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(2 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn rename_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(13_474_000 as RefTimeWeight)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(56_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn remove_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(37_720_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(114_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(2 as RefTimeWeight))
	}
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 99]`.
	fn quit_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(26_848_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(115_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(T::DbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(T::DbWeight::get().writes(2 as RefTimeWeight))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn add_registrar(r: u32, ) -> Weight {
		Weight::from_ref_time(16_649_000 as RefTimeWeight)
			// Standard Error: 5_000
			.saturating_add(Weight::from_ref_time(241_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn set_identity(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(31_322_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(252_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(312_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity SuperOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn set_subs_new(s: u32, ) -> Weight {
		Weight::from_ref_time(30_012_000 as RefTimeWeight)
			// Standard Error: 2_000
			.saturating_add(Weight::from_ref_time(3_005_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:1)
	/// The range of component `p` is `[1, 100]`.
	fn set_subs_old(p: u32, ) -> Weight {
		Weight::from_ref_time(29_623_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_100_000 as RefTimeWeight).scalar_saturating_mul(p as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes((1 as RefTimeWeight).saturating_mul(p as RefTimeWeight)))
	}
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity IdentityOf (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:100)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `s` is `[1, 100]`.
	/// The range of component `x` is `[1, 100]`.
	fn clear_identity(r: u32, s: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(34_370_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(186_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_114_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(189_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity Registrars (r:1 w:0)
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn request_judgement(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(34_759_000 as RefTimeWeight)
			// Standard Error: 4_000
			.saturating_add(Weight::from_ref_time(251_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(340_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `x` is `[1, 100]`.
	fn cancel_request(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(32_254_000 as RefTimeWeight)
			// Standard Error: 7_000
			.saturating_add(Weight::from_ref_time(159_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(347_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_fee(r: u32, ) -> Weight {
		Weight::from_ref_time(7_858_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(190_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_account_id(r: u32, ) -> Weight {
		Weight::from_ref_time(8_011_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(187_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	fn set_fields(r: u32, ) -> Weight {
		Weight::from_ref_time(7_970_000 as RefTimeWeight)
			// Standard Error: 3_000
			.saturating_add(Weight::from_ref_time(175_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(1 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity Registrars (r:1 w:0)
	// Storage: Identity IdentityOf (r:1 w:1)
	/// The range of component `r` is `[1, 19]`.
	/// The range of component `x` is `[1, 100]`.
	fn provide_judgement(r: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(24_730_000 as RefTimeWeight)
			// Standard Error: 4_000
			.saturating_add(Weight::from_ref_time(196_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(341_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity SubsOf (r:1 w:1)
	// Storage: Identity IdentityOf (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	// Storage: Identity SuperOf (r:0 w:100)
	/// The range of component `r` is `[1, 20]`.
	/// The range of component `s` is `[1, 100]`.
	/// The range of component `x` is `[1, 100]`.
	fn kill_identity(r: u32, s: u32, x: u32, ) -> Weight {
		Weight::from_ref_time(44_988_000 as RefTimeWeight)
			// Standard Error: 10_000
			.saturating_add(Weight::from_ref_time(201_000 as RefTimeWeight).scalar_saturating_mul(r as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(1_126_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(2_000 as RefTimeWeight).scalar_saturating_mul(x as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(3 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes((1 as RefTimeWeight).saturating_mul(s as RefTimeWeight)))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 99]`.
	fn add_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(36_768_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(115_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(2 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn rename_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(13_474_000 as RefTimeWeight)
			// Standard Error: 0
			.saturating_add(Weight::from_ref_time(56_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(1 as RefTimeWeight))
	}
	// Storage: Identity IdentityOf (r:1 w:0)
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 100]`.
	fn remove_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(37_720_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(114_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(3 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(2 as RefTimeWeight))
	}
	// Storage: Identity SuperOf (r:1 w:1)
	// Storage: Identity SubsOf (r:1 w:1)
	/// The range of component `s` is `[1, 99]`.
	fn quit_sub(s: u32, ) -> Weight {
		Weight::from_ref_time(26_848_000 as RefTimeWeight)
			// Standard Error: 1_000
			.saturating_add(Weight::from_ref_time(115_000 as RefTimeWeight).scalar_saturating_mul(s as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().reads(2 as RefTimeWeight))
			.saturating_add(RocksDbWeight::get().writes(2 as RefTimeWeight))
	}
}
