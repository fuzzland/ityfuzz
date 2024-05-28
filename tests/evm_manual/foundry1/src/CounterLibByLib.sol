// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

library t1 {
    function del(uint256 a) external returns (uint256) {
        return a - 1;
    }
}

library t2 {
    using t1 for uint256;

    function test(uint256 _t) external returns (uint256) {
        return _t.del();
    }
}

contract CounterLibByLib {
    using t2 for uint256;

    uint256 public x = 100;

    function test3() public {
        x.test();
    }
}
