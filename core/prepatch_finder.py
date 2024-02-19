import os

from config import REPOSITORY_CODE_PATH


class PrePatchFinder(object):
    @staticmethod
    def find_pre_commit(git_repository, commit_id):
        assert os.path.exists(os.path.join(REPOSITORY_CODE_PATH, git_repository)), \
            f"[-] REPOSITORY_CODE_PATH of {git_repository} not exists"
        cwd = os.getcwd()
        os.chdir(os.path.join(REPOSITORY_CODE_PATH, git_repository))
        pre_patch_commit_id = os.popen(f"git rev-parse {commit_id}~").read().strip()
        os.chdir(cwd)
        return pre_patch_commit_id
