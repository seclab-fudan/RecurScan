import os

from config import REPOSITORY_CODE_PATH


class PatchModifiedFilesAnalyzer(object):
    @staticmethod
    def find_modified_files(git_repository, commit_id):
        assert os.path.exists(os.path.join(REPOSITORY_CODE_PATH, git_repository)), \
            f"[-] REPOSITORY_CODE_PATH of {git_repository} not exists"
        cwd = os.getcwd()
        os.chdir(os.path.join(REPOSITORY_CODE_PATH, git_repository))
        modified_files = os.popen(f"git diff-tree --no-commit-id --name-only -r {commit_id}").read().strip()
        os.chdir(cwd)
        return modified_files.split("\n")

    @staticmethod
    def find_all_modified_files(repository, fixing_commits):
        files = set()
        for fixing_commit in fixing_commits:
            for __ in PatchModifiedFilesAnalyzer.find_modified_files(repository, fixing_commit, ):
                files.add(__)
        return files
