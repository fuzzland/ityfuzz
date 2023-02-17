pragma solidity ^0.8.0;

function bug() {
    bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
    assembly {
        let p := add(msize(), 0x20)
        mstore(p, t2)
        log1(p, 0x20, 0x133337)
    }
}
