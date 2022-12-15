import glob
import subprocess
import os
import time


TIMEOUT_BIN = "timeout" if os.name == "posix" else "gtimeout"


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
    p = subprocess.run(" ".join([
        TIMEOUT_BIN, "1m", "./cli/target/release/cli", "-t", f"'{path}/*'",  "-f"]),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )

    if b"target hit" not in p.stderr:
        print(p.stderr.decode("utf-8"))
        print(p.stdout.decode("utf-8"))
        raise Exception(f"Failed to fuzz {path}")

    # clean up
    os.system(f"rm -rf {path}/*.abi")
    os.system(f"rm -rf {path}/*.bin")

    print(f"=== Success: {path}, Finished in {time.time() - start_time}s")


def build_fuzzer():
    # build fuzzer
    os.chdir("cli")
    subprocess.run(["cargo", "build", "--release"])
    os.chdir("..")


build_fuzzer()
for i in glob.glob("tests/*"):
    # if "verilog-2" in i:
    #     continue
    print("Starting test: " + i)
    test_one(i)

print("All tests passed")