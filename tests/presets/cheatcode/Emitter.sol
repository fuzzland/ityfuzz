// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Emitter {
    uint256 public thing;

    event Something(uint256 indexed topic1, uint256 indexed topic2, uint256 indexed topic3, uint256 data);
    event SomethingNonIndexed(uint256 data);

    function emitEvent(uint256 topic1, uint256 topic2, uint256 topic3, uint256 data) public {
        emit Something(topic1, topic2, topic3, data);
    }

    function emitMultiple(
        uint256[2] memory topic1,
        uint256[2] memory topic2,
        uint256[2] memory topic3,
        uint256[2] memory data
    ) public {
        emit Something(topic1[0], topic2[0], topic3[0], data[0]);
        emit Something(topic1[1], topic2[1], topic3[1], data[1]);
    }

    function emitAndNest() public {
        emit Something(1, 2, 3, 4);
        emitNested(Emitter(address(this)), 1, 2, 3, 4);
    }

    function emitOutOfExactOrder() public {
        emit SomethingNonIndexed(1);
        emit Something(1, 2, 3, 4);
        emit Something(1, 2, 3, 4);
        emit Something(1, 2, 3, 4);
    }

    function emitNested(Emitter inner, uint256 topic1, uint256 topic2, uint256 topic3, uint256 data) public {
        inner.emitEvent(topic1, topic2, topic3, data);
    }
}
