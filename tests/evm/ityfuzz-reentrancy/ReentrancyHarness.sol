// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

interface ICallback {
    function something() external;
}

contract ReentrancyHarness {
    event AssertionFailed(string message);

    uint256 public balances = 1;
    uint256 public is_success;
    address public attacker;

    constructor() {
        attacker = address(new ReentryCallback(address(this)));
    }

    function a(address x) public {
        require(balances > 0, "No balance");

        // Effects before interactions: prevent re-entry with a live balance.
        balances = 0;
        is_success += 1;

        ICallback(x).something();
    }

    function trigger() external {
        a(attacker);
    }

    function callback() external {
        require(msg.sender == attacker, "Unauthorized callback");

        if (is_success < 3) {
            a(attacker);
        }
    }

    function b() external {
        if (is_success == 3) {
            emit AssertionFailed("Bug");
        }
    }
}

contract ReentryCallback {
    ReentrancyHarness public target;

    constructor(address targetAddress) {
        target = ReentrancyHarness(targetAddress);
    }

    function something() external {
        target.callback();
    }
}
