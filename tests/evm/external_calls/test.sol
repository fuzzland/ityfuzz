pragma solidity ^0.8.14;
import "../../../solidity_utils/lib.sol";

/// 0xDA9dfA130Df4dE4673b89022EE50ff26f6EA73Cf
contract Caller {
    function wtf(bytes memory data) public {
        address(0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8).call(data);
    }
}


/// 0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8
contract Callee {
    function complex_func(uint256 x) public {
        require(msg.sender == address(0xDA9dfA130Df4dE4673b89022EE50ff26f6EA73Cf), "Only the owner can call this function");
        require(x > 0, "0");
        bug();
    }
}