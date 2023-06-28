pragma solidity ^0.8.0;

function bug() {
    bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
    assembly {
        let p := add(msize(), 0x20)
        mstore(p, t2)
        log1(p, 0x20, 0x133337)
    }
}

function typed_bug(uint64 typed) {
    typed = typed * 0x100 + 0x78;
    bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
    assembly {
        let p := add(msize(), 0x20)
        mstore(p, t2)
        log1(p, 0x20, typed)
    }
}
