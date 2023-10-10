module struct_tests::test {
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

    public fun check(token1: Token, token2: Token, _token3: Token, _token4: Token, _token5: Token, _token6: Token, _token7: Token, _token8: Token) {
        if (token1.amount == 8301237461249124 && token2.amount == 338913231) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }
}
