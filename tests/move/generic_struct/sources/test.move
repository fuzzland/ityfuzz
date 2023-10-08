module generic_struct::test {
    use sui::event;

    struct AAAA__fuzzland_move_bug has drop, copy, store {
        info: u64
    }

    struct Token<T: store + drop> has store, drop {
        amount: T,
    }

    public fun mint(amount: u256): Token<u256> {
        Token { amount }
    }

    public fun check(token1: Token<u256>, token2: Token<u256>) {
        if (token1.amount == 8301237461249124 && token2.amount == 338913231) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }
}
