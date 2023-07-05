// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../../solidity_utils/lib.sol";

contract main {

    function process_three(bytes2 a) public returns (string memory){
    	//require(a == 0xabcd, "incorrect input");
        bug();
	return 'Hello Contracts';
    }
}
