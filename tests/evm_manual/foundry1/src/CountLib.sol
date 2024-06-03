// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

library ImplementationLib1 {
    event testEvent(address txOrigin, address msgSenderAddress, address _from);

    function doSomething() public {
        emit testEvent(tx.origin, msg.sender, address(this));
    }
}

library ImplementationLib2 {
    event testEvent(address txOrigin, address MsgSenderAddress, address _from);

    function doSomething() public {
        emit testEvent(tx.origin, msg.sender, address(this));
    }
}

contract CallingContract {
    function callImplementationLib() public {
        ImplementationLib1.doSomething();
        ImplementationLib2.doSomething();
    }
}

contract NewCallingContract {
    CallingContract cc;

    constructor() {
        cc = new CallingContract();
    }

    function test_new() public {
        cc.callImplementationLib();
    }
}
