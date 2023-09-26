// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {IERC20} from "./interfaces/IERC20.sol";
import {IWMATIC} from "./interfaces/IWMATIC.sol";
import {IWMATICV2} from "./interfaces/IWMATICV2.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import "./libraries/TransferHelper.sol";
import "../../../solidity_utils/lib.sol";

/// @title The core logic for the WMATICV2 contract

contract Bounty {
    IWMATICV2 public WMATICV2;
    bool public isHacked;
    address public WMATIC;
    address public winner;

    constructor() {
        WMATIC = address(0x8);
        WMATICV2 = IWMATICV2(address(0xDA3AF9c51F6953988a46C21d43A5152AFC7f389d));
    }

    function getBounty() public payable returns (bool) {
        //        if (WMATICV2.totalSupply() != WMATICV2.balance()) {
        //            bug();
        //        }
        uint256 delta = WMATICV2.totalSupply() >= WMATICV2.balance()
            ? WMATICV2.totalSupply() - WMATICV2.balance()
            : WMATICV2.balance() - WMATICV2.totalSupply();

        uint256 tolerance = WMATICV2.balance() / 10;
        if (delta > tolerance) {
            bug();

            // reward the first finder
            isHacked = true;
            //            IERC20(WMATIC).transfer(msg.sender, IERC20(WMATIC).balanceOf(address((this))));
            winner = address(msg.sender);
        }

        return isHacked;
    }
}
