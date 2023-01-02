import requests
from bs4 import BeautifulSoup
import re
from multiprocessing import Pool


NETWORK = "https://etherscan.io/address"

finder = re.compile(r"id\":\"(.+?)\"")

def fetch(seg):
    # print(seg)
    r = requests.get("https://immunefi.com/bounty/" + seg)
    soup = BeautifulSoup(r.text, "html.parser")
    for i in soup.find_all("a", href=True):
        # todo: take care of ens
        if NETWORK in i["href"] and ".eth" not in i["href"]:
            try:
                print(i["href"].split("address/")[1].split("?")[0].split("#")[0].replace("/", ""))
            except Exception as e:
                print(i["href"])
                raise e



if __name__ == "__main__":
    with Pool(10) as p:
        p.map(fetch, finder.findall(requests.get("https://immunefi.com/explore/").text))


