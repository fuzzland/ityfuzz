module hello_world::hello_world {
    use sui::event;

    struct AAAA__fuzzland_move_bug has drop, copy, store {
        info: u64
    }

    struct Token has store, drop {
        amount: u256,
    }

    public fun mint(amount: u256): Token {
        return Token { amount: amount }
    }

    public fun check(token1: Token, token2: Token, token3: Token, token4: Token, token5: Token, token6: Token, token7: Token, token8: Token) {
        if (token1.amount == 8301237461249124 && token2.amount == 338913231) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }
}