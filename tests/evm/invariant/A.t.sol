// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// import "../src/A.sol";

contract ExampleContract1 {
    uint256 public val1;
    uint256 public val2;
    uint256 public val3;

    function addToA(uint256 amount) external {
        val1 += amount;
        val3 += amount;
    }

    function addToB(uint256 amount) external {
        val2 += amount;
        val3 += amount;
    }
}

contract InvariantExample1 {
    ExampleContract1 foo;
    uint256 public val1 = 1;
    uint256 public val2 = 2;
    uint256 public val3 = 1;

    function addToA(uint256 amount) external {
        val1 += amount;
        val3 += amount;
    }

    function addToB(uint256 amount) external {
        val2 += amount;
        val3 += amount;
    }

    function setUp() external {
        foo = new ExampleContract1();
    }

    function invariant_1() public returns (bool) {
        return (true);
    }

    function invariant_false() public returns (bool) {
        assert(val1 + val2 == val3);
        return false;
    }

    function invariant_B() public {
        assert(val1 + val2 > 0);
    }

    // function invariant_revert() public {
    //     // assertEq(foo.val1() + val2, val3);
    //     revert();
    // }
}
