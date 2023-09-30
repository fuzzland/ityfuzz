// SPDX-License-Identifier: MIT
pragma solidity ^0.8.15;

import {IERC20} from "./interfaces/IERC20.sol";
import {IWMATIC} from "./interfaces/IWMATIC.sol";
import {IWMATICV2} from "./interfaces/IWMATICV2.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import "./libraries/TransferHelper.sol";
import "../../../solidity_utils/lib.sol";

/// @title The core logic for the WMATICV2 contract
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }
}

contract WMATICV2 is IWMATICV2, ReentrancyGuard {
    /*
    ======== Verilog CTF - Web3Dubai Conference @ 2022 =============================== 
    This is our newly designed WMATICV2 token, unlike the old version of the WMATIC
    the new contract will be more stylish with supports of depositing multi MATIC
    derivative assets to convert into WMATICV2 token.

    Scenarios:
    deposit MATIC -> mint WMATICV2 token
    deposit WMATIC -> mint WMATICV2 token
    deposit WMATIC <> WMATICV2 LP -> mint WMATICV2 token (early stage incentive for switching)

    Besides, our team designed a early stage bounty insurance contract to monitor the 
    safety of the WMATICV2. 

    Find your way to hack around ! But I am sure its really safe.
    */

    string public name = "Wrapped Matic Version 2";
    string public symbol = "WMATICV2";
    uint8 public decimals = 18;
    uint256 private _totalSupply;
    uint256 private _balanceOfMatic;
    address public WMATIC;
    address public LP;

    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address _wmatic) {
        WMATIC = address(0x8);
        LP = address(0x0);
    }

    // errors
    error CallFailed();

    receive() external payable {
        _depositMATIC(msg.sender);
    }

    function depositMATIC() public payable nonReentrant {
        _depositMATIC(msg.sender);
    }

    function depositWMATIC(uint256 amount) external nonReentrant {
        _depositWMATIC(amount);
    }

    ///@notice need to approve both LP token & WMATIC token to the contract
    function depositLP(uint256 amount) external nonReentrant {
        require(LP != address(0), "SET LP");
        require(IERC20(LP).balanceOf(msg.sender) >= amount, "NO ENOUGH BALANCE");
        uint256 beforeBalance = IERC20(LP).balanceOf(address(this));
        IERC20(LP).transferFrom(msg.sender, address(this), amount);
        uint256 afterBalance = IERC20(LP).balanceOf(address(this));
        require(afterBalance - beforeBalance >= amount, "TRANSFER NOT ENOUGH");
        // redeem back WMATIC & WMATICV2 back to user
        IUniswapV2Pair(LP).transferFrom(msg.sender, LP, amount);
        (uint256 amount0, uint256 amount1) = IUniswapV2Pair(LP).burn(msg.sender);
        // transfer the WMATIC to this address and convert it to V2
        if (IUniswapV2Pair(LP).token0() == address(this)) {
            // if token0 is WMATICV2 -> amount1 is WMATIC
            _depositWMATIC(amount1);
            transfer(msg.sender, amount0);
        } else {
            // if token0 is WMATIC -> amount1 is WMATICV2
            _depositWMATIC(amount0);
            transfer(msg.sender, amount1);
        }
    }

    function redeem(uint256 amount) public nonReentrant {
        require(balanceOf[msg.sender] >= amount, "NO ENOUGH BALANCE");
        balanceOf[msg.sender] -= amount;
        _totalSupply -= amount;
        (bool success,) = payable(msg.sender).call{value: amount}("");
        if (!success) {
            revert CallFailed();
        }
        _updateBalanceOfMatic(amount, false);
        emit Withdrawal(msg.sender, amount);
    }

    function redeemWMATIC(uint256 amount) public nonReentrant {
        require(balanceOf[msg.sender] >= amount, "NO ENOUGH BALANCE");
        balanceOf[msg.sender] -= amount;
        _totalSupply -= amount;
        TransferHelper.safeTransfer(WMATIC, msg.sender, amount);
        _updateBalanceOfMatic(amount, false);
        emit Withdrawal(msg.sender, amount);
    }

    function totalSupply() external view override returns (uint256) {
        return _totalSupply;
    }

    function balance() external view override returns (uint256) {
        return _balanceOfMatic;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad);
        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }

    function _depositMATIC(address to) internal {
        if (to != WMATIC) {
            balanceOf[to] += msg.value;
        }
        _totalSupply += msg.value;
        _updateBalanceOfMatic(msg.value, true);
        emit Deposit(to, msg.value);
    }

    function _depositWMATIC(uint256 amount) internal {
        require(IERC20(WMATIC).balanceOf(msg.sender) >= amount, "NO ENOUGH BALANCE");
        uint256 beforeBalance = IERC20(WMATIC).balanceOf(address(this));
        IERC20(WMATIC).transferFrom(msg.sender, address(this), amount);
        uint256 afterBalance = IERC20(WMATIC).balanceOf(address(this));
        require(afterBalance - beforeBalance >= amount, "TRANSFER NOT ENOUGH");
        balanceOf[msg.sender] += amount;
        _totalSupply += amount;
        _updateBalanceOfMatic(amount, true);
    }

    function _updateBalanceOfMatic(uint256 amount, bool add) internal {
        _balanceOfMatic = add ? _balanceOfMatic += amount : _balanceOfMatic -= amount;
    }
}
