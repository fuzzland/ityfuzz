pragma solidity ^0.8.0;

function bug() {
    bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
                            /* fuzzland */
    uint256 ityfuzz_flags = 0x66757A7A6C616E64000000000000000000000000000000000000000000000000;
    ityfuzz_flags += 0x37;
    assembly {
        let p := add(msize(), 0x40)
        mstore(p, t2)
        log1(p, 0x40, ityfuzz_flags)
    }
}

function typed_bug(uint64 typed) {
                            /* fuzzland */
    uint256 ityfuzz_flags = 0x66757A7A6C616E64000000000000000000000000000000000000000000000000;
    uint64 typed = typed * 0x100 + 0x78;
    ityfuzz_flags += typed;
    bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
    assembly {
        let p := add(msize(), 0x40)
        mstore(p, t2)
        log1(p, 0x40, ityfuzz_flags)
    }
}
