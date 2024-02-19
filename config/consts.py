import re
import os
import json
from .path import DATA_INPUT_PATH

obj = json.load(fp=open(os.path.join(DATA_INPUT_PATH, "repo_url.json"), 'r', encoding='utf-8'))

GIT_URL = "https://github.com/"

GIT_REPOSITORY_TO_ACCOUNT_MAP = {}
for repo_name, repo_url in obj.items():
    account = repo_url.replace(GIT_URL, '').split('/')[0]
    GIT_REPOSITORY_TO_ACCOUNT_MAP[repo_name] = account

GIT_ACCOUNT_TO_REPOSITORY_MAP = {V: K for K, V in GIT_REPOSITORY_TO_ACCOUNT_MAP.items()}

GIT_URL_DICT = {git_repository: f"https://github.com/{git_account}/{git_repository}" for git_repository, git_account
                in GIT_REPOSITORY_TO_ACCOUNT_MAP.items()}

PHP_EXTENSION = ["php", "inc", "phtml"]

