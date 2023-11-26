## Off-chain Changes

You can run the integration test by running the following command:
```bash
python3 integration_test.py
```
This will attempt to see whether the fuzzer can hit `bug()` in all projects in tests/ folder.


## On-chain Changes
Ensure you have a local proxy running at `http://localhost:5003`.

Following command shall find bugs:
```bash
./target/release/cli -o -t 0xBcF6e9d27bf95F3F5eDDB93C38656D684317D5b4,0x5d6c48f05ad0fde3f64bab50628637d73b1eb0bb -c POLYGON --onchain-block-number 35690977  -f -i -p --onchain-local-proxy-addr http://localhost:5003
./target/release/cli -o -t 0x10ED43C718714eb63d5aA57B78B54704E256024E,0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907,0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3 -c BSC --onchain-block-number 23695904 -f -i --onchain-local-proxy-addr http://localhost:5003
```

Following command shall not find bugs:
```bash

```