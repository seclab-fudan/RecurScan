import json
import logging
import os
import re

logger = logging.getLogger(__name__)

import Levenshtein
from typing import Union, List, Set
from config import STORAGE_PATH, DATA_INPUT_PATH
from core.anchor_node import BaseNode
from copy import deepcopy
from py2neo import Graph
from core.neo4j_engine import Neo4jEngine
from core.ast2code import Ast2CodeFactory
from core.neo4j_engine.const import *


class StorageHelper(object):
    @staticmethod
    def compile_path(anchor_node: BaseNode, base_path=STORAGE_PATH):
        path = os.path.join(base_path, anchor_node.git_repository, anchor_node.version,
                            f"{anchor_node.node_id}")
        create_dir_if_exists(path)
        return path

    @staticmethod
    def get_series(anchor_node: BaseNode) -> list:
        path = StorageHelper.compile_path(anchor_node)
        file_name = os.path.join(path, f'series-{anchor_node.node_id}.json')
        return json.load(fp=open(file_name, 'r'))

    @staticmethod
    def store_series(anchor_node: BaseNode, obj: Union[List, Set], readable=None) -> bool:
        path = StorageHelper.compile_path(anchor_node)
        file_name = os.path.join(path, f'series-{anchor_node.node_id}.json')
        with open(file_name, 'w') as f:
            json.dump(obj=sorted(obj), fp=f)
        return True


class StringMatcher(object):
    @staticmethod
    def similarity_array(org_str: str, given: List[str], method="jaro", prehandle_func=None) -> List[float]:
        if prehandle_func is not None:
            org_str = prehandle_func(org_str)
            given = prehandle_func(given)
        score_vector = [Levenshtein.jaro(org_str, i) for i in given]
        return score_vector

class StringFilter(object):
    HTML_ENTITY_TBL = [
            (" ", "&nbsp;", "&#160;"),
            ("<", "&lt;", "&#60;"),
            (">", "&gt;", "&#62;"),
            ("&", "&amp;", "&#38;"),
            ("\"", "&quot;", "&#34;"),
            ("'", "&apos;", "&#39;"),
    ]

    ABBREVIATION_TBL = [
            ("does not", "doesn't"),
            ("do not", "don't"),
            ("must not", "mustn't"),
            ("should not", "shouldn't"),
            ("can not", "can't"),
            ("is not", "isn't"),
            ("are not", "aren't"),
    ]

    @staticmethod
    def replace_abbreviation(string: str) -> str:
        for raw, r1 in StringFilter.ABBREVIATION_TBL:
            string.replace(r1, raw)
        return string

    @staticmethod
    def replace_html_entity(string: str) -> str:
        for raw, r1, r2 in StringFilter.HTML_ENTITY_TBL:
            string.replace(r1, raw)
            string.replace(r2, raw)
        return string

    @staticmethod
    def filter_normalized_commit_id(commit_id: str) -> str:
        return commit_id.replace("_prepatch", "").replace("_postpatch", "")

    @staticmethod
    def filter_map_key_to_git_repository_and_version(map_key):
        index = len(map_key) - 1 - map_key[::-1].index('-')
        return map_key[:index], map_key[index + 1:]

    @staticmethod
    def filter_git_account_and_repository(commit_url):
        res = deepcopy(commit_url)
        try:
            import re
            res = re.findall(
                    r"https://github.com/(.*?)/(.*?)/commit/", res
            )
            res = res[0]
            git_account, git_repository = res
            return git_account, git_repository
        except Exception as e:
            return None, None

def create_dir_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        dir_path = PATH
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
    if isinstance(PATH, list):
        for _path in PATH:
            create_dir_if_exists(_path)


def remove_file_if_exists(PATH: str or list):
    if isinstance(PATH, str):
        if os.path.exists(PATH):
            os.remove(PATH)
    if isinstance(PATH, list):
        for _path in PATH:
            if os.path.exists(_path):
                os.remove(_path)


def check_str_in_list(string: str, iterable: List[str]):
    if not isinstance(string, str):
        return False
    if string == '':
        logger.info("empty string will not be checked !")
        return False
    for it in iterable:
        if string in it:
            return True
    return False


def check_list_in_str(string: str, iterable: List[str]):
    if not isinstance(string, str):
        return False
    if string == '':
        logger.info("empty string will not be checked !")
        return False
    for it in iterable:
        if it in string:
            return True
    return False

def get_expression_and_conditions(analyzer: Neo4jEngine, path: List[int], condition_ids: List[int]):
        path_copy = path.copy()
        sink_node_id = path_copy.pop()
        arg_list = analyzer.ast_step.find_function_arg_node_list(analyzer.get_node_itself(sink_node_id))
        for arg_node in arg_list:
            path_copy.append(arg_node[NODE_INDEX])
        arg_expressions = Ast2CodeFactory.extract_code(analyzer, path_copy, normalize_level=2)[-len(arg_list):]
        conditions = Ast2CodeFactory.extract_code(analyzer, condition_ids, with_memory=False)
        return arg_expressions, conditions
