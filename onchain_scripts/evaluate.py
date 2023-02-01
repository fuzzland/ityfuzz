import os
import sys
from multiprocessing import Pool
import subprocess

if not os.path.exists('target.txt'):
    print('No target.txt file found. Run "python3 immunefi.py > target.txt" first.')
    sys.exit(1)

BIN = "../cli/target/release/cli"


def clip(content):
    if len(content) > 10000:
        return content[-9999:]
    return content

def run(target):
    cmd = f'timeout 30m {target}'
    print(cmd)
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    print("exit code: ", process.returncode)
    # print("stderr: ", stderr.decode('utf-8'))

    exec_sec = []
    for i in stdout.decode('utf-8').split('\n'):
        if 'exec/sec: ' in i:
            exec_sec.append(int(i.split('exec/sec: ')[1].split(' ')[0]))

    if len(exec_sec) != 0:
        mean_exec_sec = sum(exec_sec) / len(exec_sec)
        if mean_exec_sec < 500:
            with open("slow.txt", "a") as f:
                f.write('------------------------\n')
                # f.write(cmd + '\n')
                f.write(target + '\n')
                f.write(clip(stdout.decode('utf-8')) + '\n')
                f.write('------------------------\n')

    if "Found a solution" in stdout.decode('utf-8'):
        with open("solution.txt", "a") as f:
            f.write('------------------------\n')
            # f.write(cmd + '\n')
            f.write(target + '\n')
            f.write(clip(stdout.decode('utf-8')) + '\n')
            f.write('------------------------\n')

    if "`RUST_BACKTRACE=1`" in stderr.decode('utf-8'):
        with open("crash.txt", "a") as f:
            f.write('------------------------\n')
            # f.write(cmd + '\n')
            f.write(target + '\n')
            f.write(clip(stderr.decode('utf-8')) + '\n')
            f.write('------------------------\n')



# run('0x007FE7c498A2Cf30971ad8f2cbC36bd14Ac51157')
if __name__ == "__main__":
    with Pool(3) as p:
        p.map(run, open('target.txt', 'r').read().split('\n'))
