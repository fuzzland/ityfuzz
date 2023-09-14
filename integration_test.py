import glob
import random
import subprocess
import os
import time


TIMEOUT_BIN = "timeout" if os.name == "posix" else "gtimeout"

def read_onchain_tests():
    tests = ""
    with open("onchain_tests.txt", "r") as file:
        tests = file.read()
    
    tests = tests.split("\n")
    tests = [test.split("\t") for test in tests]
    return tests

def test_one(path):
    # cleanup
    os.system(f"rm -rf {path}/build")

    # compile with solc
    p = subprocess.run(
        " ".join(["solc", f"{path}/*.sol", "-o", f"{path}/",
                  "--bin", "--abi", "--overwrite", "--base-path", "."]),
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if b"Error" in p.stderr or b"Error" in p.stdout:
        print(f"Error compiling {path}")
        return

    # run fuzzer and check whether the stdout has string success
    start_time = time.time()
    cmd = [TIMEOUT_BIN, "3m", "./cli/target/release/cli", "evm", "-t", f"'{path}/*'",  "-f", "--panic-on-bug"]

    if "concolic" in path:
        cmd.append("--concolic --concolic-caller")

    p = subprocess.run(" ".join(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )

    if b"target bug found" not in p.stderr \
            and b"bug() hit" not in p.stdout \
            and b"[typed_bug]" not in p.stdout \
            and b"[selfdestruct]" not in p.stdout \
            and b"[echidna_bug]" not in p.stdout\
            and b"Found violations!" not in p.stdout:
        print("================ STDERR =================")
        print(p.stderr.decode("utf-8"))
        print("================ STDOUT =================")
        print(p.stdout.decode("utf-8"))
        print(f"=== Failed to fuzz {path}")
    else:
        print(f"=== Success: {path}, Finished in {time.time() - start_time}s")

    # clean up
    # os.system(f"rm -rf {path}/*.abi")
    # os.system(f"rm -rf {path}/*.bin")


def test_onchain(test):

    if len(test) != 4:
        print(f"=== Invalid test: {test}")
        return

    # randomly sleep for 0 - 30s to avoid peak traffic
    time.sleep(30 * random.random())

    contract_addresses, block_number, chain, name= test[3], test[2], test[1], test[0]
    if chain not in ["eth", "bsc"]:
        print(f"=== Unsupported chain: {chain}")
        return
    cmd = [
        TIMEOUT_BIN, 
        # set timeout to 5m because it takes longer time to sync the chain
        "5m",
        "./cli/target/release/cli", "evm", "-o", 
        "-t", contract_addresses, 
        "-c", chain, 
        "--onchain-block-number", str(block_number), 
        "-f", "-i", "-p"
    ]

    start_time = time.time()

    # try 3 times in case of rpc failure
    for i in range(3):
        p = subprocess.run(" ".join(cmd),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=True)

        if b"Found violations!" in p.stdout:
            print(f"=== Success: Tested onchain for contracts: {name}, Finished in {time.time() - start_time}s")
            return

        time.sleep(30)
            
    print("================ STDERR =================")
    print(p.stderr.decode("utf-8") + " ".join(cmd))
    print("================ STDOUT =================")
    print(p.stdout.decode("utf-8"))
    print(f"=== Failed to test onchain for contracts: {name}")

def build_fuzzer():
    # build fuzzer
    os.chdir("cli")
    subprocess.run(["cargo", "build", "--release"])
    os.chdir("..")

def update_cargo_toml():
    with open("Cargo.toml", "r") as file:
        content = file.read()

    if '"flashloan_v2"' in content:
        return

    if '"cmp"' in content:
        content = content.replace('"cmp"', '"cmp","flashloan_v2"')

    with open("Cargo.toml", "w") as file:
        file.write(content)

    print("Cargo.toml has been updated!")

def build_flash_loan_v2_fuzzer():
    update_cargo_toml()
    # build fuzzer
    os.chdir("cli")
    subprocess.run(["cargo", "build", "--release"])
    os.chdir("..")


import multiprocessing

if __name__ == "__main__":
    build_fuzzer()
    with multiprocessing.Pool(3) as p:
        p.map(test_one, glob.glob("./tests/evm/*/", recursive=True))

    build_flash_loan_v2_fuzzer()

    tests = read_onchain_tests()

    with multiprocessing.Pool(3) as p:
        p.map(test_onchain, tests)
