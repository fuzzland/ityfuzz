// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

contract CheatcodeTest is Test {
    bytes32 slot0 = bytes32(uint256(0));

    event LogCompleted(uint256 indexed topic1, bytes data);

    function test() external {
        string memory s = string(abi.encodePacked(block.timestamp));
        address randomAddr = makeAddr(s);
        uint256 random = uint160(randomAddr);
        bytes32 randomBytes = bytes32(random);
        bytes memory contractCode = bytes("0x6080");
        VmSafe.CallerMode callerMode;
        address msgSender;
        address txOrigin;
        address oldSender = msg.sender;
        address oldOrigin = tx.origin;

        assertNotEq(block.timestamp, random);
        vm.warp(random);
        assertEq(block.timestamp, random);

        assertNotEq(block.number, random);
        vm.roll(random);
        assertEq(block.number, random);

        assertNotEq(block.basefee, random);
        vm.fee(random);
        assertEq(block.basefee, random);

        assertNotEq(block.prevrandao, random);
        vm.prevrandao(randomBytes);
        assertEq(block.prevrandao, random);

        assertNotEq(block.chainid, 100);
        vm.chainId(100);
        assertEq(block.chainid, 100);

        assertNotEq(tx.gasprice, random);
        vm.txGasPrice(random);
        assertEq(tx.gasprice, random);

        assertNotEq(block.coinbase, randomAddr);
        vm.coinbase(randomAddr);
        assertEq(block.coinbase, randomAddr);

        assertNotEq(randomBytes, vm.load(randomAddr, slot0));
        vm.store(randomAddr, slot0, randomBytes);
        assertEq(randomBytes, vm.load(randomAddr, slot0));

        assertEq(0, randomAddr.balance);
        vm.deal(randomAddr, 100);
        assertEq(100, randomAddr.balance);

        assertEq(0, address(randomAddr).code.length);
        vm.etch(randomAddr, contractCode);
        assertEq(contractCode, address(randomAddr).code);

        // Test readCallers, prank

        // readCallers before prank
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.None));
        assertEq(msgSender, oldSender);
        assertEq(txOrigin, oldOrigin);
        // Only prank msg.sender
        vm.prank(randomAddr);
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.Prank));
        assertEq(msgSender, randomAddr);
        assertEq(txOrigin, oldOrigin);
        // Consume the prank
        (bool _success,) = randomAddr.call(abi.encodeWithSignature("withdraw()"));
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.None));
        assertEq(msgSender, oldSender);
        assertEq(txOrigin, oldOrigin);
        // Prank msg.sender and tx.origin
        vm.prank(randomAddr, randomAddr);
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.Prank));
        assertEq(msgSender, randomAddr);
        assertEq(txOrigin, randomAddr);
        // Consume the prank
        (_success,) = randomAddr.call(abi.encodeWithSignature("withdraw()"));

        // Test startPrank / stopPrank

        // Only startPrank msg.sender
        vm.startPrank(randomAddr);
        (_success,) = randomAddr.call(abi.encodeWithSignature("withdraw()"));
        // abi call will not consume the prank
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.RecurrentPrank));
        assertEq(msgSender, randomAddr);
        assertEq(txOrigin, oldOrigin);
        vm.stopPrank();
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.None));
        assertEq(msgSender, oldSender);
        assertEq(txOrigin, oldOrigin);
        // startPrank msg.sender and tx.origin
        vm.startPrank(randomAddr, randomAddr);
        (_success,) = randomAddr.call(abi.encodeWithSignature("withdraw()"));
        // abi call will not consume the prank
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.RecurrentPrank));
        assertEq(msgSender, randomAddr);
        assertEq(txOrigin, randomAddr);
        vm.stopPrank();

        // Test record / accesses
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(this));
        assertEq(0, reads.length);
        assertEq(0, writes.length);
        vm.record();
        // When slot0 is written, it is also read
        slot0 = bytes32(uint256(1));
        // Read slot0
        bytes32 value;
        assembly {
            value := sload(0)
        }
        (reads, writes) = vm.accesses(address(this));
        assertEq(2, reads.length);
        assertEq(1, writes.length);

        // Test recordLogs / getRecordedLogs
        vm.recordLogs();
        emit LogCompleted(10, "operation completed");
        VmSafe.Log[] memory entries = vm.getRecordedLogs();
        assertEq(entries.length, 1);
        assertEq(entries[0].topics[0], keccak256("LogCompleted(uint256,bytes)"));
        assertEq(entries[0].topics[1], bytes32(uint256(10)));
        assertEq(abi.decode(entries[0].data, (string)), "operation completed");
    }

    function testExpectRevertWithoutReason() public {
        vm.expectRevert(bytes(""));
        Reverter(0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf).revertWithoutReason();
    }

    function testExpectRevertWithMessage() public {
        vm.expectRevert("revert");
        Reverter(0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf).revertWithMessage("revert");
    }

    function testExpectRevertCustomError() public {
        Reverter reverter = Reverter(0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf);
        vm.expectRevert(abi.encodePacked(Reverter.CustomError.selector));
        reverter.revertWithCustomError();
    }

    function testExpectRevertNested() public {
        Reverter reverter = Reverter(0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf);
        Reverter inner = Reverter(0xaAbeB5BA46709f61CFd0090334C6E71513ED7BCf);
        vm.expectRevert("nested revert");
        reverter.nestedRevert(inner, "nested revert");
    }
}
