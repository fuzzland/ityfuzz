// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import "./Reverter.sol";
import "./Emitter.sol";
import "./Caller.sol";
import "./Pranker.sol";

contract CheatcodeTest is Test {
    bytes32 slot0 = bytes32(uint256(0));

    event LogCompleted(uint256 indexed topic1, bytes data);

    // test expected emits
    event Something(uint256 indexed topic1, uint256 indexed topic2, uint256 indexed topic3, uint256 data);
    event SomethingNonIndexed(uint256 data);

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
        (callerMode, msgSender, txOrigin) = vm.readCallers();
        assertEq(uint256(callerMode), uint256(VmSafe.CallerMode.None));
        assertEq(msgSender, oldSender);
        assertEq(txOrigin, oldOrigin);

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

    // Test prank with Pranker -------------------------------

    function setPrankerCode() internal {
        /*
        contract Pranker {
            function check_sender() public view {
                require(msg.sender == address(0x100));
            }

            function check_sender_origin() public view {
                require(msg.sender == address(0x100));
                require(tx.origin == address(0x200));
            }
        }
        */
        bytes memory prankerCode =
            hex"6080604052348015600f57600080fd5b506004361060325760003560e01c8063b52c835e146037578063dd3cf6c714603f575b600080fd5b603d6045565b005b603d6061565b3361010014605257600080fd5b3261020014605f57600080fd5b565b3361010014605f57600080fdfea2646970667358221220d9426db6cf358b3b3ed9bfbfa87a7a0dcf3e3d8d836bf226fce186085697085d64736f6c63430008150033";
        vm.etch(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae, prankerCode);
    }

    function testPrank() public {
        setPrankerCode();
        Pranker panker = Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae);

        vm.prank(address(0x100));
        panker.check_sender();

        vm.prank(address(0x100), address(0x200));
        panker.check_sender_origin();
    }

    function testExpectRevertBeforePrank() public {
        setPrankerCode();
        vm.expectRevert(bytes(""));
        Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae).check_sender();
    }

    function testExpectRevertAfterConsumePrank() public {
        setPrankerCode();
        Pranker panker = Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae);

        vm.prank(address(0x100));
        // abi call consumes the prank
        panker.check_sender();
        vm.expectRevert(bytes(""));
        panker.check_sender();
    }

    function testExpectRevertPrankSenderOrigin() public {
        setPrankerCode();
        vm.expectRevert(bytes(""));
        Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae).check_sender_origin();
    }

    function testStartStopPrank() public {
        setPrankerCode();
        Pranker panker = Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae);

        vm.startPrank(address(0x100));
        // abi can be called multiple times
        panker.check_sender();
        panker.check_sender();
        vm.stopPrank();

        vm.startPrank(address(0x100), address(0x200));
        panker.check_sender_origin();
        panker.check_sender_origin();
        vm.stopPrank();
    }

    function testExpectRevertAfterStopPrank() public {
        setPrankerCode();
        Pranker panker = Pranker(0xB6BeB0D5ec26D7Ea5E224826fF6b924CeCD253Ae);

        vm.startPrank(address(0x100));
        vm.stopPrank();
        vm.expectRevert(bytes(""));
        panker.check_sender();
    }

    // Test revert -------------------------------

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

    // Test emit -------------------------------

    function testExpectEmitMultiple() public {
        vm.expectEmit();
        emit Something(1, 2, 3, 4);
        vm.expectEmit();
        emit Something(5, 6, 7, 8);

        Emitter(0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD).emitMultiple(
            [uint256(1), uint256(5)], [uint256(2), uint256(6)], [uint256(3), uint256(7)], [uint256(4), uint256(8)]
        );
    }

    function testExpectedEmitMultipleNested() public {
        vm.expectEmit();
        emit Something(1, 2, 3, 4);
        vm.expectEmit();
        emit Something(1, 2, 3, 4);

        Emitter(0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD).emitAndNest();
    }

    function testExpectEmitMultipleWithArgs() public {
        vm.expectEmit(true, true, true, true);
        emit Something(1, 2, 3, 4);
        vm.expectEmit(true, true, true, true);
        emit Something(5, 6, 7, 8);

        Emitter(0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD).emitMultiple(
            [uint256(1), uint256(5)], [uint256(2), uint256(6)], [uint256(3), uint256(7)], [uint256(4), uint256(8)]
        );
    }

    function testExpectEmitCanMatchWithoutExactOrder() public {
        vm.expectEmit(true, true, true, true);
        emit Something(1, 2, 3, 4);
        vm.expectEmit(true, true, true, true);
        emit Something(1, 2, 3, 4);

        Emitter(0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD).emitOutOfExactOrder();
    }

    function testExpectEmitCanMatchWithoutExactOrder2() public {
        vm.expectEmit(true, true, true, true);
        emit SomethingNonIndexed(1);
        vm.expectEmit(true, true, true, true);
        emit Something(1, 2, 3, 4);

        Emitter(0xC6829a4b1a9bCCc842387F223dd2bC5FA50fd9eD).emitOutOfExactOrder();
    }

    // Test expected calls -------------------------------

    function testExpectCallWithData() public {
        Caller target = Caller(0xBE8d2A52f21dce4b17Ec809BCE76cb403BbFbaCE);
        vm.expectCall(address(target), abi.encodeWithSelector(target.add.selector, 1, 2));
        target.add(1, 2);
    }

    function testExpectMultipleCallsWithData() public {
        Caller target = Caller(0xBE8d2A52f21dce4b17Ec809BCE76cb403BbFbaCE);
        vm.expectCall(address(target), abi.encodeWithSelector(target.add.selector, 1, 2));
        // Even though we expect one call, we're using additive behavior, so getting more than one call is okay.
        target.add(1, 2);
        target.add(1, 2);
    }

    function testExpectCallWithValue() public {
        Caller target = Caller(0xBE8d2A52f21dce4b17Ec809BCE76cb403BbFbaCE);
        vm.expectCall(address(target), 1, abi.encodeWithSelector(target.pay.selector, 2));
        target.pay{value: 1}(2);
    }
}
