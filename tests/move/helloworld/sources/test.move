// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// A basic Hello World example for Sui Move, part of the Sui Move intro course:
/// https://github.com/sui-foundation/sui-move-intro-course
///
module hello_world::hello_world {
    use sui::event;

    // use std::string;
    // use sui::object::{Self, UID};
    // use sui::transfer;
    // use sui::tx_context::{Self, TxContext};
    //
    // /// An object that contains an arbitrary string
    // struct HelloWorldObject has key, store {
    //     id: UID,
    //     /// A string contained in the object
    //     text: string::String
    // }

    struct DonutBought has copy, drop {
        info: u32
    }



    public entry fun mint(idx: u64) {
        if (idx == 0) {
            event::emit(DonutBought { info: 88 });
        } else {
            event::emit(DonutBought { info: 123 });
        }
    }

}