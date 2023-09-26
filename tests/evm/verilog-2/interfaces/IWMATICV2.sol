pragma solidity ^0.8.15;

interface IWMATICV2 {
    function totalSupply() external view returns (uint256);

    function balance() external view returns (uint256);
}
