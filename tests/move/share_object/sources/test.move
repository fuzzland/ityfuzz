module share_object::test {
    use sui::object::{Self, UID};
    use sui::event;
    use sui::transfer;
    use sui::tx_context::TxContext;

    struct AAAA__fuzzland_move_bug has drop, copy, store {
        info: u64
    }

    struct Token has store, key {
        id: UID,
        amount: u256,
    }

    public fun mint(ctx: &mut TxContext, amount: u256) {
        let id = object::new(ctx);
        transfer::share_object(Token { id: id, amount: amount });
    }

    public fun check(token1: &mut Token) {
        if (token1.amount == 1872104128401294) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }
}
