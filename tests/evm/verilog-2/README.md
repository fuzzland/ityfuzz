<div align="center">
  <img alt="verilog logo" src="https://raw.githubusercontent.com/Verilog-Solutions/.github/main/assets/verilog-logo.svg" width="300"  />
  <p align="center">
    <a href="https://github.com/sindresorhus/awesome">
      <img alt="awesome list badge" src="https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg">
    </a>
  </p>

  <p align="center">Verilog Web3Dubai CTF Challenge #2 </p>

</div>

---

## Introduction

| Verilog 2022 web3dubai CTF challenge #2

This is our newly designed WMATICV2 token, unlike the old version of the WMATIC <br />
the new contract will be more stylish with supports of depositing multi MATIC <br />
derivative assets to convert into WMATICV2 token. <br />

**Scenarios:** <br />

- deposit MATIC -> mint WMATICV2 token <br />
- deposit WMATIC -> mint WMATICV2 token <br />
- deposit WMATIC <> WMATICV2 LP -> mint WMATICV2 token (for early stage liquidity incentive users) <br />

Besides, our team designed a bounty insurance contract to monitor the <br /> safety of the WMATICV2. If you can crack it, bounty is yours!

Find your way to hack around! But I am sure it's really safe.

## Explanation

- WMATICV2 contract

  ```solidity
  // contract safety purely depends on these 2 variables
  interface IWMATICV2 {

    // minted token balance
    function totalSupply() external view returns (uint256);

    // actually eth balance
    function balance() external view returns (uint256);

  }
  ```

- the criteria is:
  ```solidity
  // more than 10% of the difference been considered as an exploit detected
  function status () external view returns (bool) {
      uint256 delta = WMATICV2.totalSupply() >= WMATICV2.balance() ? WMATICV2.totalSupply() - WMATICV2.balance() : WMATICV2.balance() - WMATICV2.totalSupply();
      uint256 tolerance = WMATICV2.balance() / 10;
      if (delta > tolerance) {
        return true;
      }
      return false;
  }
  ```

## Deployed Addresses

| Contract Name      | Address                                    |
|--------------------|--------------------------------------------|
| wMatic Contract    | 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270 |
| wMatic V2 Contract | 0x5D6C48F05ad0fde3f64baB50628637d73B1eB0BB |
| Bounty Contract    | 0xBcF6e9d27bf95F3F5eDDB93C38656D684317D5b4 |
