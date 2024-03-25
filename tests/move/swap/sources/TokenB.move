module swap::ctfb {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use std::option;

    friend swap::vault;

    struct CTFB has drop {}

    struct MintB<phantom CTFB> has key, store {
        id: UID,
        cap: TreasuryCap<CTFB>
    }

    fun init(witness: CTFB, ctx: &mut TxContext) {
        // Get a treasury cap for the coin and give it to the transaction sender
        let (treasury_cap, metadata) = coin::create_currency<CTFB>(witness, 1, b"CTF", b"CTF", b"Token for move ctf", option::none(), ctx);
        let mint = MintB<CTFB> {
            id: object::new(ctx),
            cap:treasury_cap
        };
        transfer::share_object(mint);
        transfer::public_freeze_object(metadata);
    }

    public(friend) fun mint_for_vault<CTFB>(mint: MintB<CTFB>, ctx: &mut TxContext): Coin<CTFB> {
        let coinb = coin::mint<CTFB>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintB<CTFB> {
            id: idb,
            cap: capb
        } = mint;
        object::delete(idb);
        transfer::public_freeze_object(capb);
        coinb
    }

}