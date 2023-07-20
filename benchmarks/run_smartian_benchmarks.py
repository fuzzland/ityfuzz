import os

BASE = "../cli/target/release/cli"

def build_sol(in_file: str, out_dir: str):
    os.system(
        f"solc --bin --abi --overwrite --optimize --optimize-runs 99999 --combined-json bin-runtime,srcmap-runtime {in_file} -o {out_dir}")



def run_ityfuzz(name, folder):
    os.system(f"timeout 5m {BASE} -t '{folder}/*' --work-dir out/{name} 1>logs/{name} 2>logs/{name}.err")


def run_ityfuzz_coverage(name, folder):
    os.system(f"{BASE} -t '{folder}/*' --work-dir out/{name} --replay-file 'out/{name}/corpus/*_replayable' 1>logs/{name} 2>logs/{name}.err")



import multiprocessing as mp


if __name__ == '__main__':
    # compile files
    # for file in os.listdir("Smartian-Artifact/benchmarks/B1/sol/"):
    #     print(file)
    # prefix = file.split(".")[0]
    # out_dir = f"Smartian-Artifact/benchmarks/B1/compiled/{prefix}"
    # if file.endswith(".sol"):
    #     build_sol(f"Smartian-Artifact/benchmarks/B1/sol/{file}", out_dir)
    #
    # # run ityfuzz
    args = []
    for i in os.listdir("Smartian-Artifact/benchmarks/B1/compiled/"):
        args.append((i, f"Smartian-Artifact/benchmarks/B1/compiled/{i}"))
    # with mp.Pool(4) as p:
    #     p.starmap(run_ityfuzz, args)

    # get coverage
    with mp.Pool(4) as p:
        p.starmap(run_ityfuzz_coverage, args)
