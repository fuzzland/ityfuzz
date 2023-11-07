// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract AdultOtter {
    bool public solved = false;

    event AssertionFailed(string message);

    function pwn(uint[16] memory code) public { 
      uint[16] memory a;
      uint[16] memory b;

      for (uint i = 0; i < 16; i++) {
        assert(1337 * i < code[i] && code[i] < 1337 * (i + 1));
      }

      // emit AssertionFailed("Bug");

      
      for (uint i = 0; i < 16; i++) {
        a[i] = i**i * code[i];
      }

      for (uint i = 1; i < 16; i++) {
        b[i] = (2**255 + code[i] - 7 * a[i] + b[i-1]) % 2**64;
      }
      assert(b[15] == 0);
      emit AssertionFailed("Bug2");
      /*
      emit AssertionFailed("Bug");
      */
    }
}
