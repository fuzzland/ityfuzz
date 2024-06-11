import glob
import os
import random
import subprocess
import time

TIMEOUT_BIN = "timeout" if os.name == "posix" else "gtimeout"

crashed_any = False


def read_onchain_tests():
    tests = ""
    with open("onchain_tests.txt", "r") as file:
        tests = file.read().strip()

    tests = tests.strip().split("\n")
    tests = [test.split("\t") for test in tests]
    return tests


def test_one(path):
    global crashed_any
    print(path)
    # cleanup
    os.system(f"rm -rf {path}/build")

    # compile with solc
    p = subprocess.run(
        " ".join(
            [
                "solc",
                f"{path}/*.sol",
                "-o",
                f"{path}/",
                "--bin",
                "--abi",
                "--overwrite",
                "--base-path",
                ".",
                "--combined-json",
                "bin-runtime,srcmap-runtime",
            ]
        ),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if b"Error" in p.stderr or b"Error" in p.stdout:
        print(f"Error compiling {path}")
        crashed_any = True
        return

    # run fuzzer and check whether the stdout has string success
    start_time = time.time()
    cmd = [
        TIMEOUT_BIN,
        "30s",
        "./target/release/ityfuzz",
        "evm",
        "-t",
        f"'{path}/*'",
        "-f",
    ]
    # exit(0)

    if "concolic" in path:
        cmd.append("--concolic --concolic-caller")

    if "taint" in path:
        cmd.append("--sha3-bypass")

    print(" ".join(cmd))

    p = subprocess.run(
        " ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )

    if b"Found vulnerabilities!" not in p.stdout:
        print("================ STDERR =================")
        print(p.stderr.decode("utf-8"))
        print("================ STDOUT =================")
        print(p.stdout.decode("utf-8"))
        print(f"=== Failed to fuzz {path}")
        if b"panicked" in p.stderr or b"panicked" in p.stdout:
            crashed_any = True
        return False, path
    else:
        print(f"=== Success: {path}, Finished in {time.time() - start_time}s")
        return True, path

    # clean up
    # os.system(f"rm -rf {path}/*.abi")
    # os.system(f"rm -rf {path}/*.bin")


def test_onchain(test):
    global crashed_any
    if len(test) != 4:
        print(f"=== Invalid test: {test}")
        crashed_any = True
        return

    # randomly sleep for 0 - 30s to avoid peak traffic
    time.sleep(60 * random.random())

    contract_addresses, block_number, chain, name = test[3], test[2], test[1], test[0]

    if chain not in ["eth", "bsc", "polygon"]:
        print(f"=== Unsupported chain: {chain}")
        crashed_any = True
        return

    etherscan_key = os.getenv(f"{chain.upper()}_ETHERSCAN_API_KEY")
    if etherscan_key is None:
        print(f"=== No etherscan api key for {chain}")
        crashed_any = True
        return
    my_env = os.environ.copy()
    my_env["ETH_RPC_URL"] = os.getenv(f"{chain.upper()}_RPC_URL")
    my_env["RUST_BACKTRACE"] = "1"

    cmd = [
        TIMEOUT_BIN,
        # set timeout to 5m because it takes longer time to sync the chain
        "5m",
        "./target/release/ityfuzz",
        "evm",
        "-t",
        contract_addresses,
        "-c",
        chain,
        "-b",
        str(block_number),
        "-f",
        "--onchain-etherscan-api-key",
        etherscan_key,
        "--work-dir",
        f"w_{name}",
        # "--run-forever"
    ]

    start_time = time.time()

    # try 3 times in case of rpc failure
    for i in range(3):
        p = subprocess.run(
            " ".join(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            env=my_env,
        )

        if b"Found vulnerabilities" in p.stdout:
            print(
                f"=== Success: Tested onchain for contracts: {name}, Finished in {time.time() - start_time}s"
            )
            open(f"res_{name}.txt", "w+").write(
                p.stderr.decode("utf-8")
                + " ".join(cmd)
                + "\n"
                + p.stdout.decode("utf-8")
            )
            return
        if b"panicked" in p.stderr or b"panicked" in p.stdout:
            crashed_any = True
            print("================ STDERR =================")
            print(p.stderr.decode("utf-8"))
            print("================ STDOUT =================")
            print(p.stdout.decode("utf-8"))
        time.sleep(30)

    print(f"=== Failed to test onchain for contracts: {name}")
    open(f"res_{name}.txt", "w+").write(
        p.stderr.decode("utf-8") + " ".join(cmd) + "\n" + p.stdout.decode("utf-8")
    )


def build_fuzzer():
    # build fuzzer
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "cmp dataflow evm print_txn_corpus full_trace",
            "--no-default-features",
        ]
    )


def build_flash_loan_v2_fuzzer():
    # build fuzzer
    subprocess.run(
        [
            "cargo",
            "build",
            "--release",
            "--features",
            "cmp dataflow evm print_txn_corpus full_trace force_cache",
            "--no-default-features",
        ]
    )


import multiprocessing
import sys

if __name__ == "__main__":
    actions = []

    if len(sys.argv) > 1:
        if sys.argv[1] == "onchain":
            actions.append("onchain")
        elif sys.argv[1] == "offchain":
            actions.append("offchain")
    else:
        actions = ["onchain", "offchain"]

    if "offchain" in actions:
        build_fuzzer()
        with multiprocessing.Pool(3) as p:
            results = p.map(test_one, glob.glob("./tests/evm/*", recursive=True))
        failed = [result for result in results if result and not result[0]]
        if failed:
            print("❌ Failed tests:")
            for f in failed:
                print(f[1])
            exit(1)

    if "onchain" in actions:
        build_flash_loan_v2_fuzzer()
        tests = read_onchain_tests()
        with multiprocessing.Pool(10) as p:
            p.map(test_onchain, tests)

    if crashed_any:
        exit(1)
