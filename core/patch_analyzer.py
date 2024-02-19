import json
import logging
import os
import re
import subprocess
from typing import *

import py2neo

from config.consts import PHP_EXTENSION
from config.path import REPOSITORY_CODE_PATH, STORAGE_PATH
from core.helper import check_list_in_str, create_dir_if_exists, StorageHelper, StringFilter
from core.modified_line import ModifiedLine
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.prepatch_finder import PrePatchFinder
from core.source_code_helper import SourceCodeHelper

logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)


def diff_hunk_analysis(content, block, aiming="pre"):
    assert aiming == "pre" or aiming == "post", "aiming arg must be `pre` or `post`"
    result = []
    slow, fast = block
    slow, fast = slow - 1, fast - 1
    bur = re.findall(r'^@@ ([-+])([0-9].*?)(,[0-9].*?)? ([-+])([0-9].*?)(,[0-9].*?)? @@', content[slow])
    if not bur:
        return result
    bur = bur[0]
    pre_flag, pre_start, post_flag, post_start = bur[0], int(bur[1]), bur[3], int(bur[4])
    slow, fast = slow + 1, fast
    while slow <= fast:
        if content[slow].startswith(pre_flag) and not content[slow].startswith(pre_flag * 3):
            if aiming == "pre":
                result.append(pre_start)
            pre_start += 1
        elif content[slow].startswith(post_flag) and not content[slow].startswith(post_flag * 3):
            if aiming == "post":
                result.append(post_start)
            post_start += 1
        else:
            post_start += 1
            pre_start += 1
        slow += 1
    return result


def diff_files_analysis(content, block):
    slow, fast = block
    slow, fast = slow - 1, fast - 1
    if '/dev/null' in content[slow]:
        return None
    return re.findall(r'^--- a/(.*?)$', content[slow])[0]


class PatchAnalyzer(object):
    def get_patch_modification_file_list(self):
        file_list = []
        diff_storage_path = self.__complie_storage_path('diff')
        if not os.path.exists(diff_storage_path):
            self.do_diff(diff_storage_path)
        content = open(diff_storage_path, 'r', encoding='utf-8').read().split("\n")
        l1 = []
        l2 = []
        r = {}
        MAGIC_BITS = 16
        MAGIC_NUMBER = (1 << MAGIC_BITS) - 1
        for i, _r in enumerate(content, 1):
            if _r.startswith("@@"):
                l1.append(i)
            elif _r.startswith("---"):
                l2.append(i)
        l2.append(content.__len__())
        l1.append(content.__len__())

        for l2_i, l2_j in zip(l2[:-1], l2[1:]):
            structure = []
            for l1_i, l1_j in zip(l1[:-1], l1[1:]):
                if content[l1_j - 1 - 2].startswith('---'):
                    l1_j = l2_j
                if l1_i >= l2_i and l1_j <= l2_j:
                    structure.append((l1_i, l1_j))
            r[l2_i << MAGIC_BITS | l2_j] = structure
        for k, v in r.items():
            file_name = diff_files_analysis(content, (k >> MAGIC_BITS, k & MAGIC_NUMBER))
            if file_name is None:
                continue
            if file_name.split('.')[-1] not in PHP_EXTENSION:
                continue
            file_list.append(file_name)
        return file_list

    def __init__(self, analysis_framework_pre: Neo4jEngine,
                 analysis_framework_post: Neo4jEngine,
                 commit_url, commit_id, prepatch_commit_id=None, cve_id=None):
        self.analyzer_pre = analysis_framework_pre
        self.analyzer_post = analysis_framework_post
        self.commit_url = commit_url
        self.account, self.repository = StringFilter.filter_git_account_and_repository(self.commit_url)
        self.commit_id = commit_id
        self.source_code_helper = SourceCodeHelper()
        self.prepatch_commit_id = prepatch_commit_id if prepatch_commit_id is not None else \
            PrePatchFinder.find_pre_commit(self.repository, self.commit_id)
        self.cve_id = cve_id
        self.FUNC_EXIT_CACHE = []
        self.FUNC_NO_EXIT_CACHE = []
        self.ALL_NEW_LINES = []

    def __complie_storage_path(self, backend):
        res_dir = os.path.join(STORAGE_PATH, "patch_analysis_result")
        storage_dir = os.path.join(STORAGE_PATH, "patch_analysis_result", backend.__str__())
        create_dir_if_exists([res_dir, storage_dir])
        storage_file = os.path.join(storage_dir, f"{self.commit_id}.{backend}")
        return storage_file

    def clear_cache(self, ):
        self.FUNC_EXIT_CACHE = []
        self.FUNC_NO_EXIT_CACHE = []
        self.ALL_NEW_LINES = []

    def do_diff(self, file_name):
        git_repository = re.findall(r'https://github\.com/.*?/(.*?)/', self.commit_url)[0]
        current_path = os.getcwd()
        git_info_path = os.path.join(REPOSITORY_CODE_PATH, git_repository)
        os.chdir(git_info_path)
        p = subprocess.Popen(args=f'git diff {self.prepatch_commit_id} {self.commit_id}   --raw -p --no-color',
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=True
                             )
        if p.stdout:
            open(file_name, 'wb').write(p.stdout.read())
        else:

            raise SystemError()
        os.chdir(current_path)

    def find_modify_lines_from_diff(self):
        self.clear_cache()
        diff_storage_path = self.__complie_storage_path('diff')
        if not os.path.exists(diff_storage_path):
            self.do_diff(diff_storage_path)
        content = open(diff_storage_path, 'r').read().split("\n")
        l1 = []
        l2 = []
        r = {}
        MAGIC_BITS = 16
        MAGIC_NUMBER = (1 << MAGIC_BITS) - 1
        for i, _r in enumerate(content, 1):
            if _r.startswith("@@"):
                l1.append(i)
            elif _r.startswith("---"):
                l2.append(i)
        l2.append(content.__len__())
        l1.append(content.__len__())

        for l2_slow, l2_fast in zip(l2[:-1], l2[1:]):
            structure = []
            for l1_slow, l1_fast in zip(l1[:-1], l1[1:]):
                if content[l1_fast - 1 - 2].startswith('---'):
                    l1_fast = l2_fast
                if l1_slow >= l2_slow and l1_fast <= l2_fast:
                    structure.append((l1_slow, l1_fast))
            r[l2_slow << MAGIC_BITS | l2_fast] = structure
        patch_modifications = {}
        for k, v in r.items():
            file_name = diff_files_analysis(content, (k >> MAGIC_BITS, k & MAGIC_NUMBER))
            if file_name is None:
                continue
            start_line = []
            if file_name.split('.')[-1] not in PHP_EXTENSION:
                continue
            for _v in v:
                result = diff_hunk_analysis(content, _v, aiming="pre")
                result = self._affected_line_transformer(result, file_name)
                start_line.extend(result)

            if start_line.__len__() == 0:
                for _v in v:
                    result_post = diff_hunk_analysis(content, _v, aiming="post")
                    if result_post.__len__() != 0:
                        result = self._affected_line_transformer_ext(result_post, file_name)
                        start_line.extend(result)
            patch_modifications[file_name] = start_line
        return patch_modifications

    def _affected_line_transformer(self, lines, file_name):
        rt_result = set()
        file_id_pre = self.analyzer_pre.fig_step.get_file_name_node(file_name)[NODE_FILEID]
        for line in lines:
            for _node in self.analyzer_pre.basic_step.match(LABEL_AST, **{
                    NODE_FILEID: file_id_pre,
                    NODE_LINENO: line,
            }):
                x = self.analyzer_pre.ast_step.get_root_node(_node)
                if x is not None:
                    rt_result.add(x)
        return rt_result

    def _affected_line_transformer_ext(self, lines, file_name):
        file_id_post = self.analyzer_post.fig_step.get_file_name_node(file_name)[NODE_FILEID]
        file_id_pre = self.analyzer_pre.fig_step.get_file_name_node(file_name)[NODE_FILEID]
        rt_result = set()
        _result = set()
        for line in lines:
            _res = self.analyzer_post.basic_step.match_first(LABEL_AST, **{
                    NODE_FILEID: file_id_post,
                    NODE_LINENO: line,
                    NODE_CHILDNUM: 0
            })
            if _res is not None and self.analyzer_post.ast_step.get_root_node(_res) is not None:
                _result.add(self.analyzer_post.ast_step.get_root_node(_res))
        _result = sorted(_result, key=lambda x: x[NODE_LINENO])
        for root_node in _result:
            l_max = 0xff43
            func_decl = self.analyzer_post.basic_step.get_node_itself(root_node[NODE_FUNCID])
            if func_decl[NODE_TYPE] in {TYPE_FUNC_DECL, TYPE_METHOD}:
                l_max = func_decl[NODE_ENDLINENO]
            if root_node[NODE_TYPE] == TYPE_CALL:
                func_name = self.analyzer_post.code_step.get_node_code(root_node)
                if func_name == "check_input_parameter":
                    _affect_param = "{}[\'{}\']".format(self.analyzer_post.code_step.get_node_code(
                            self.analyzer_post.ast_step.get_function_arg_ith_node(root_node, 1))
                            , self.analyzer_post.code_step.get_node_code(
                                    self.analyzer_post.ast_step.get_function_arg_ith_node(root_node, 0)))
                    rt_result |= self.__search_affected_param(_affect_param, file_name, min(lines), l_max, file_id_pre)
                elif func_name == "access_ensure_project_level":
                    rt_result |= set(self.analyzer_pre.ast_step.get_root_node(i) for i in
                                     self.analyzer_pre.neo4j_graph.nodes.match(LABEL_AST, **{NODE_CHILDNUM: 0,
                                                                                             NODE_FILEID: file_id_pre}) \
                                     .where(f"_.lineno>={max(lines)}"))
            elif root_node[NODE_TYPE] == TYPE_ASSIGN:
                assign_left_op = self.analyzer_post.ast_step.get_child_node(root_node)
                _affect_param = self.analyzer_post.code_step.get_node_code(assign_left_op)
                _rt_result = self.__search_affected_param(_affect_param, file_name, min(lines), l_max, file_id_pre)
                if _rt_result.__len__() == 0 and \
                        assign_left_op[NODE_TYPE] in {TYPE_DIM}:
                    if self.analyzer_post.code_step.get_ast_dim_body_code(assign_left_op):
                        _affect_param = "$" + self.analyzer_post.code_step.get_ast_dim_body_code(assign_left_op) + "["
                        _rt_result = self.__search_affected_param(_affect_param, file_name, min(lines), l_max, file_id_pre)
                rt_result |= _rt_result
        return rt_result

    def __search_affected_param(self, _affect_param, file_name, lines_min, lines_max, file_id_pre):
        rt_result = set()
        _potential_line = []
        source_path = self.source_code_helper.download_source(git_repository=self.repository,
                                                              version=self.prepatch_commit_id,
                                                              file_name=file_name)
        assert os.path.exists(source_path), f"[*] {source_path} not found"
        with open(source_path, 'r', encoding='utf8') as f:
            for lineno, content in enumerate(f.readlines(), start=1):
                if not (lines_min - 1 <= lineno <= lines_max):
                    continue
                else:
                    if check_list_in_str(content.replace("\"", "\'"), [_affect_param]):
                        _potential_line.append(lineno)
        for line in _potential_line:
            _res = self.analyzer_pre.basic_step.match_first(LABEL_AST, **{
                    NODE_FILEID: file_id_pre,
                    NODE_LINENO: line,
                    NODE_CHILDNUM: 0
            })
            if _res is not None:
                _res = self.analyzer_pre.ast_step.get_root_node(_res)
                if _res is not None:
                    rt_result.add(self.analyzer_pre.ast_step.get_root_node(_res))
        return rt_result

    def patch_analyzer_main(self, patch_modifications):
        self.clear_cache()
        modification_res = {}
        for filename, lines in patch_modifications.items():
            if filename.split('.')[-1] not in PHP_EXTENSION:
                continue
            if not lines:
                res = []
            else:
                file_node = self.analyzer_pre.fig_step.get_file_name_node(filename)
                if file_node is None:
                    continue
                res = self.collect_content(lines, file_node[NODE_FILEID])
            modification_res[filename] = res
        return modification_res

    def run_result(self):
        res_dir = os.path.join(STORAGE_PATH, "patch_analysis_result")
        res_file = os.path.join(res_dir, f"res_{self.commit_id}.json")
        patch_modifications = self.find_modify_lines_from_diff()
        res = self.patch_analyzer_main(patch_modifications)
        json.dump(obj=res, fp=open(res_file, 'w'), default=lambda x: x.__dict__)

    def collect_content(self, lines: List[int], file_id: int, ):
        res = []
        for line in lines:
            line_first = set()
            if isinstance(line, py2neo.Node):
                res.append(ModifiedLine(line[NODE_LINENO], line[NODE_INDEX], line[NODE_TYPE], ))
            else:
                for _node in self.analyzer_pre.basic_step.match(LABEL_AST, **{
                        NODE_FILEID: file_id,
                        NODE_LINENO: line,
                }):
                    line_first.add(self.analyzer_pre.ast_step.get_root_node(_node))
                line_first = sorted(list(i for i in line_first if i is not None), key=lambda x: x.identity)
                if line_first.__len__() == 0:
                    continue
                else:
                    for rr in line_first:
                        res.append(ModifiedLine(line, rr[NODE_INDEX], rr[NODE_TYPE], ))
        return sorted(res, key=lambda x: x.lineno)

    @staticmethod
    def get_content(commit_id) -> Dict:
        res_dir = os.path.join(STORAGE_PATH, "patch_analysis_result")
        html_storage_dir = os.path.join(STORAGE_PATH, "patch_analysis_result", "html")
        create_dir_if_exists([res_dir, html_storage_dir])
        res_file = os.path.join(res_dir, f"res_{commit_id}.json")
        return json.load(fp=open(res_file, 'w'), object_hook=lambda x: ModifiedLine(**x))
