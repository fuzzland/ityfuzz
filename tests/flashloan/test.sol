// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../solidity_utils/lib.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);

    function transfer(address to, uint256 amount) external returns (bool);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);}

contract main {
    uint256 is_ok = 0;

    // solution: a = 1
    function process(uint8 a) public returns (string memory){
        IERC20 deeper_token = IERC20(address(0xA0A2eE912CAF7921eaAbC866c6ef6FEc8f7E90A4));
        require(a < 2, "2");
        require(deeper_token.balanceOf(address(msg.sender)) > 0, "3");
        deeper_token.transfer(address(msg.sender), 1);
        is_ok = 1;
        return 'Hello Contracts';
    }

    function oracle_harness() public returns (bool) {
        require(is_ok > 0);
        bug();
        return true;
    }
}
