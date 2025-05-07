#!/usr/bin/env python
import argparse, os, requests, zipfile, shutil
from pathlib import Path
from synthesizer.synthesizer import Synthesizer
from synthesizer.config import *
from tempfile import NamedTemporaryFile, TemporaryDirectory, TemporaryFile

def run_cmd(cmd, timeout, out_file):
    ret = os.system(f"ASAN_OPTIONS=detect_leaks=0,detect_stack_use_after_return=1 timeout {timeout} {cmd} > {out_file} 2>&1");
    return ret >> 8

def string_to_targetub(ub_str: str) -> TargetUB:
    match ub_str:
        case "buffer-overflow" | "0" | "(0)":
            return TargetUB.BufferOverflow
        case "double-free" | "1" | "(1)":
            return TargetUB.DoubleFree
        case "null-pointer-dereference" | "2" | "(2)":
            return TargetUB.NullPtrDeref
        case "use-after-free" | "3" | "(3)":
            return TargetUB.UseAfterFree
        case "use-after-scope" | "4" | "(4)":
            return TargetUB.UseAfterScope
        case "division-by-zero" | "5" | "(5)":
            return TargetUB.DivideZero
        case "integer-overflow" | "6" | "(6)":
            return TargetUB.IntegerOverflow
        case "out-of-bound" | "7" | "(7)":
            return TargetUB.OutBound
        case "use-of-uninit" | "8" | "(8)":
            return TargetUB.UseUninit
        case _:
            return TargetUB.ERROR

def install_csmith():
    csmith_home = Path(__file__).parent / "csmith_install"
    csmith_home.mkdir(exist_ok=True)
    url = "https://codeload.github.com/csmith-project/csmith/zip/refs/tags/csmith-2.3.0"

    with NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        # 加上 User-Agent 模拟浏览器，有时候更保险
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get(url, headers=headers, stream=True)
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=8192):
            tmp.write(chunk)
        tmp_path = tmp.name

    with TemporaryDirectory() as srcdir:
        with zipfile.ZipFile(tmp_path, "r") as z:
            z.extractall(srcdir)
        src_sub = next(Path(srcdir).iterdir())  # 解压后会是 csmith-csmith-2.3.0 目录
        os.system(f"cd {src_sub} && cmake -DCMAKE_INSTALL_PREFIX={csmith_home} . && make -j4 && make install")

def check_available_csmith() -> bool:
    csmith_home = Path(__file__).parent / "csmith_install"
    if not csmith_home.exists():
        install_csmith()
    with NamedTemporaryFile(suffix=".c", mode="rb", delete=True) as tmp_src:
        ret = os.system(f"{csmith_home}/bin/csmith > {tmp_src.name}")
        if ret != 0:
            return False
        ret = os.system(f"{CC} {COMPILE_ARGS} {tmp_src.name} -o /dev/null -w")
        if ret != 0:
            return False
        return True

def generate_csmith_src() -> str:
    src = NamedTemporaryFile(suffix=".c", mode="w", delete=False)
    src.close()
    src = src.name
    csmith_exe = 'null'
    while 1:
        if Path(csmith_exe).exists():
            os.remove(csmith_exe)
        with NamedTemporaryFile(suffix="_csmith.exe", mode="w", delete=False) as f:
            f.close()
            csmith_exe = f.name
            cmd = f"{CSMITH_BIN} {CSMITH_USER_OPTIONS} --output {src}"
            ret = run_cmd(cmd, CSMITH_TIMEOUT, "/dev/null")
            if ret != 0:
                continue
            if os.path.getsize(src) >= MIN_PROGRAM_SIZE:
                cmd = f"{CC} {COMPILE_ARGS} {CSMITH_CHECK_OPTIONS} {src} -o {csmith_exe}"
                ret = run_cmd(cmd, COMPILER_TIMEOUT, "/dev/null")
                if ret != 0:
                    continue
                ret = run_cmd(csmith_exe, PROG_TIMEOUT, "/dev/null")
                if ret != 0:
                    continue
                break
            else:
                continue
    if Path(csmith_exe).exists():
        os.remove(csmith_exe)
    return src
    

if __name__=='__main__':
    parser = argparse.ArgumentParser(description="Sythesize programs with undefined behaviors.")
    parser.add_argument("--ub", required=True, help=\
                        "The type of undefined behavior to synthesize. Supported types are: \
                            (0) buffer-overflow , \
                            (1) double-free, \
                            (2) null-pointer-dereference, \
                            (3) use-after-free, \
                            (4) use-after-scope, \
                            (5) division-by-zero, \
                            (6) integer-overflow, \
                            (7) out-of-bound, \
                            (8) use-of-uninit \
                        ")
    parser.add_argument("--out", type=Path, required=True, help="The output directory to store the synthesized programs.")
    parser.add_argument("--seed", type=Path, required=False, help="Specify the seed C program to inject UB.")

    args = parser.parse_args()

    target_ub = string_to_targetub(args.ub)
    if target_ub == TargetUB.ERROR:
        print(f"Invalid undefined behavior type: {args.ub}")
        exit(1)
    if has_overlap([TargetUB.DoubleFree, TargetUB.MemoryLeak], ALL_TARGET_UB):
        TOOL_STACKTOHEAP = f'{DYNAMIC_ANALYZER}/tool-stacktoheap --mutate-prob 100' # free statements will only be inserted with p=100

    
    check_available_csmith()

    args.out.mkdir(parents=True, exist_ok=True)

    while True:
        with TemporaryDirectory() as tmp_dir:
            SYNER = Synthesizer(prob=100, tmp_dir=tmp_dir, given_ALL_TARGET_UB=[target_ub])
            if args.seed is not None:
                if not os.path.exists(args.seed):
                    print(f'The seed file `{args.seed}` does not exist!')
                    exit(1)
                
                if not str(args.seed).endswith(".c"):
                    print(f'The seed file `{args.seed}` must end with `.c`!')
                    exit(1)
                src = str(args.seed)
            else:
                src = generate_csmith_src()
            mutated_files = []
            try:
                mutated_files = SYNER.synthesizer(src, MUTATE_NUM)
            except Exception as e:
                print(f'UBGen failed with {e}')
            
            for mutated_file in mutated_files:
                shutil.copy(mutated_file, args.out)
                os.remove(mutated_file)
            
            print(f'{len(mutated_files)} mutants generated and stored in `{args.out}`')
            if args.seed is not None:
                break
            os.remove(src)
            if len(mutated_files) == 0:
                print('try again...')
                continue
        break


