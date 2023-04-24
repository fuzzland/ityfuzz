import os
import subprocess
import uuid
import signal
from werkzeug.utils import secure_filename

env = os.environ.copy()
env["RUST_BACKTRACE"] = "1"


def clip(content):
    if len(content) > 30000:
        return content[-29999:]
    return content


class ItyFuzz:
    def __init__(self):
        self.process = None
        self.out = None
        self.cancel = False

    def to_command(self):
        raise NotImplementedError("to_command not implemented")

    def run(self):
        out = str(uuid.uuid4())
        outfile = open(out, "w")
        process = subprocess.Popen(" ".join(self.to_command()), shell=True, stdout=outfile, stderr=outfile, env=env , preexec_fn=os.setsid)
        self.process = process
        self.out = out
        print(out, "started")

    def rerun(self):

        outfile = open(self.out, "w")
        self.process = subprocess.Popen(" ".join(self.to_command()), shell=True, stdout=outfile, stderr=outfile, env=env)

    def cancelit(self):
        os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        self.process.kill()
        self.process.terminate()
        self.process = None
        self.out = None

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def get_idx(self):
        return self.out

    def get_output(self):
        if self.out is None or self.cancel:
            return "Cancelled", ""
        with open(self.out, "r") as f:
            stdout = clip(f.read())
            if "source: TimedOut" in stdout:
                print("TimedOut")
                return "Timed Out", stdout
            if "Found a solution" in stdout:
                return "Found Exploit", stdout
            print(self.process.returncode)
            if "`RUST_BACKTRACE=`" in stdout or (self.process.returncode is not None and self.process.returncode > 1):
                return "Crash", stdout

            return "In Progress", stdout

    def get_extra(self):
        raise NotImplementedError("get_extra not implemented")


class ItyFuzzOnchain(ItyFuzz):
    path = "/bins/cli_onchain"

    ty = "Onchain"

    def __init__(self, json):
        print(json)
        super().__init__()
        self.json = json
        self.type = json['type']
        self.name = json['name']
        self.chain = json['chain'].upper()
        self.targets = json['targets']
        self.block_num = json['block_num']
        self.flashloan = json['flashloan']

        self.rpc = json['rpc']
        self.proxy = json['proxy']
        self.proxy = self.proxy if self.proxy else "http://localhost:5003"
        self.storage = json['storage']

        self.price_oracle = []
        for (k, v) in json['price_oracle'].items():
            if v == 'True':
                self.price_oracle.append(k)

        self.prices = json['prices']
        self.pools = json['pools']
        self.abis = json['abis']
        self.process = None
        self.out = None

    def convert_storage_fetching(self, storage):
        if storage == "debug_storageRangeAt":
            return "dump"
        return "onebyone"

    def to_command(self):
        cmd = [self.path]
        cmd += ["-o", "-i", "-p"]
        cmd += ["-t", self.targets]
        cmd += ["-c", self.chain]
        cmd += ["--onchain-block-number", self.block_num if self.block_num else "0"]

        if self.flashloan:
            cmd += ["-f"]

        cmd += ["--onchain-local-proxy-addr", self.proxy]

        # cmd += ["--ierc20-oracle", ",".join(self.price_oracle)]
        # cmd += ["--ierc20-constant-prices", str(self.prices)]
        # cmd += ["--ierc20-pools", str(self.pools)]

        # cmd += ["--onchain-abis", str(self.abis)]

        cmd += ["--onchain-storage-fetching", self.convert_storage_fetching(self.storage)]

        if self.chain == "other":
            cmd += ["--onchain-url", self.rpc]
            cmd += ["--onchain-chain-id", self.chain]
            cmd += ["--onchain-chain-name", "other"]
        cmd += ["--flashloan-price-oracle onchain"]
        return cmd

    def get_extra(self):
        return self.json


class ItyFuzzOffChin(ItyFuzz):
    path = "/bins/cli_offchain"

    ty = "OffChain"

    def __init__(self, json):
        print(json)
        super().__init__()
        self.file_path = "'./uploads/" + secure_filename(json['uuid']) + "/*'"
        self.name = json['name']

    def to_command(self):
        cmd = [self.path]
        cmd += ["-t", self.file_path]
        return cmd

    def get_extra(self):
        return {
            "name": self.name
        }
