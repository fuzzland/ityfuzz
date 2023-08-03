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

    struct AAAA__fuzzland_move_bug has drop, copy, store {
        info: u64
    }



    public entry fun mint(idx: u8) {
        if (idx == 12) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }

}