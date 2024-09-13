// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;
import "solidity_utils/lib.sol";

contract SOL {
    Test public tt;
    function setUp() public {
        tt = new Test();
    }

    function test() public returns (uint) {
        address account = address(tt);
        uint size;
        assembly {
            size := extcodesize(account)
        }
        if (size > 65) {
            bug();
        }
        return size;
    }
}

contract Test {

}
