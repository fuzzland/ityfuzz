module swap::ctfa {
    use sui::coin::{Self, Coin, TreasuryCap};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::object::{Self, UID};
    use std::option;

    friend swap::vault;

    struct CTFA has drop {}

    struct MintA<phantom CTFA> has key, store{
        id: UID,
        cap: TreasuryCap<CTFA>
    }

    fun init(witness: CTFA, ctx: &mut TxContext){
        // Get a treasury cap for the coin and give it to the transaction sender
        let (treasury_cap, metadata) = coin::create_currency<CTFA>(witness, 1, b"CTF", b"CTF", b"Token for move ctf", option::none(), ctx);
        let mint = MintA<CTFA> {
            id: object::new(ctx),
            cap:treasury_cap
        };
        transfer::share_object(mint);
        transfer::public_freeze_object(metadata);
    }

    public(friend) fun mint_for_vault<CTFA>(mint: MintA<CTFA>, ctx: &mut TxContext): Coin<CTFA> {
        let coinb = coin::mint<CTFA>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintA<CTFA> {
            id: ida,
            cap: capa
        } = mint;
        object::delete(ida);
        transfer::public_freeze_object(capa);
        coinb
    }

}