import os
import json
import sys

__all__ = ["CONFIG_PATH",
           "LOG_PATH",
           "STORAGE_PATH",
           "SINK_CACHE_PATH",
           "SOURCE_CODE_PATH",
           "REPOSITORY_CODE_PATH",
           "DATA_INPUT_PATH",
           "DATABASE_PATH",
           "RESULT_PATH",
           "NEO4J_CONFIGURE_MAP_PATH",
           "PWD"
           ]

CONFIG_PATH = os.path.realpath(os.path.dirname(__file__))

PWD = os.path.realpath(".")
DATABASE_PATH = os.path.join(PWD, "databases")
LOG_PATH = os.path.join(PWD, 'log')
STORAGE_PATH = os.path.join(PWD, "storage")
SINK_CACHE_PATH = os.path.join(STORAGE_PATH, "sink_cache")
SOURCE_CODE_PATH = os.path.join(PWD, "rcs_meta", "source_code_cache")
REPOSITORY_CODE_PATH = os.path.join(PWD, "rcs_meta", "repository_cache")
DATA_INPUT_PATH = os.path.join(PWD, 'dataset')
RESULT_PATH = os.path.join(PWD, "result")
NEO4J_CONFIGURE_MAP_PATH = os.path.join(CONFIG_PATH, 'neo4j.json')

def __create_dir_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        dir_path = PATH
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    if isinstance(PATH, list):
        for _path in PATH:
            __create_dir_if_exists(_path)


__create_dir_if_exists([
        LOG_PATH,
        STORAGE_PATH,
        SOURCE_CODE_PATH,
        REPOSITORY_CODE_PATH,
        DATA_INPUT_PATH,
        DATABASE_PATH
])

current_path = os.getcwd()
os.chdir(REPOSITORY_CODE_PATH)
obj = json.load(fp=open(os.path.join(DATA_INPUT_PATH, "repo_url.json"), 'r', encoding='utf-8'))
tries = 0
is_clone_success = True

while tries < 3:
    for repo_name, repo_url in obj.items():
        if not os.path.exists(os.path.join(REPOSITORY_CODE_PATH, repo_name)):
            print(os.path.join(REPOSITORY_CODE_PATH, repo_name), "not exist", "clone it", flush=True)
            io = os.popen("git clone " + repo_url + " 2>&1").read()
            print(io)
            if "fatal" in io:
                is_clone_success = False
    if is_clone_success:
        break
    tries += 1
    
if not is_clone_success:
    print("[-] Failed to clone repositories. Please retry after a while.")
    print("Exiting...")
    sys.exit()
os.chdir(current_path)
