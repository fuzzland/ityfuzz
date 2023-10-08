module hello_world::test {
    use sui::event;

    struct AAAA__fuzzland_move_bug has drop, copy, store {
        info: u64
    }

    public entry fun mint(idx: u256, idx2: u256) {
        if (idx == 8301237461249124 && idx2 == 8301237461249124) {
            event::emit(AAAA__fuzzland_move_bug { info: 1 });
        }
    }
}
