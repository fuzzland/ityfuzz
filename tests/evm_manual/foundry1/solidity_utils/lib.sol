pragma solidity ^0.8.0;

library FuzzLand {
    event AssertionFailed(string message);

    function bug() internal {
        emit AssertionFailed("Bug");
    }

    function typed_bug(string memory data) internal {
        emit AssertionFailed(data);
    }

}


function bug()  {
    FuzzLand.bug();
}

function typed_bug(string memory data)  {
    FuzzLand.typed_bug(data);
}
