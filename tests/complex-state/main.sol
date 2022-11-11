// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

contract main {
    // Public variables of the token
    uint8 public decimals;
//    // 18 decimals is the strongly suggested default, avoid changing it
//
//    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() {
//        totalSupply = 1000000000 * 10 ** uint256(18);  // Update total supply with the decimal amount
//        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
//        name = "s";                                   // Set the name for display purposes
//        symbol = "s";                               // Set the symbol for display purposes
    }


    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
    returns (bool success) {
//        bytes32 t2 = bytes32(uint256(uint160(msg.sender)));
//        assembly {
//            let p := add(msize(), 0x20)
//            mstore(p, t2)
//            log1(p, 0x20, 0x133337)
//        }
        allowance[msg.sender][_spender] = _value;
        return true;
    }
}
