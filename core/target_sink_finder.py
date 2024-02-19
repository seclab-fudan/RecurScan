import logging
from typing import Set
import py2neo
import os
import json

from core.anchor_node import AnchorNode
from config import STORAGE_PATH
from core.model import PHP_BUILT_IN_FUNCTIONS
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)

COMMON_NODE_TYPES = [
        TYPE_CALL, TYPE_METHOD_CALL, TYPE_STATIC_CALL,
        TYPE_INCLUDE_OR_EVAL,
        TYPE_ECHO, TYPE_PRINT, TYPE_EXIT
]

FUNCTION_MODEL = {
        7: ["include", "require", "include_once", "require_once"],
        2: ["file", "file_get_contents", "readfile", "fopen"],
        1: ["unlink", "rmdir"],
        12: ["file_put_contents", "fopen", "fwrite"],
        10: ["echo", "print", "print_r", "die"],
        4: ["exec", "passthru", "proc_open", "system", "shell_exec", "popen", "pcntl_exec"],
        3: ["eval", 'create_function', 'assert', 'array_map', 'preg_replace'],
        6: ["copy", "fopen", "move_uploaded_file", "rename"],
        13: ["header", ],
        8: ["unserialize", ],
        9: ["pg_query", "pg_send_query", "pg_prepare", "mysql_query", "mysqli_prepare", "mysqli_query",
            "mysqli_real_query"]
}

class AnchorNodeList(Set):
    def __init__(self):
        super(AnchorNodeList, self).__init__()

    def add(self, __object, analyzer: Neo4jEngine) -> None:
        _obj_ast = analyzer.basic_step.get_node_itself(__object.node_id)
        if analyzer.pdg_step.is_tracable(_obj_ast=_obj_ast):
            super(AnchorNodeList, self).add(__object)

    def add_without_check(self, __object: AnchorNode):
        super(AnchorNodeList, self).add(__object)

class TargetSinkFinder(object):
    def __compile_potential_sinks(self):
        for vuln_type in FUNCTION_MODEL.keys():
            self.potential_sinks[vuln_type]: AnchorNodeList[AnchorNode] = AnchorNodeList()

    def __complie_storage_path(self):
        storage_dir = os.path.join(STORAGE_PATH, "sink_cache")
        if not os.path.exists(storage_dir):
            os.mkdir(storage_dir)
        self.sink_storage_path = os.path.join(storage_dir, f"{self.git_repository}.json")

    def __init__(self, analysis_framework: Neo4jEngine, git_repository, cve_id=None):
        self.analyzer = analysis_framework
        self.git_repository = git_repository
        self.potential_sinks = {}
        self.__compile_potential_sinks()
        self.__complie_storage_path()

    def f_insert(self, n, vuln_type, judge_type=0b0001, loc=-1):
        try:
            self.potential_sinks[vuln_type].add(
                    AnchorNode.from_node_instance(
                            n, judge_type=judge_type, git_repository=self.git_repository,
                            func_name=self.analyzer.code_step.get_node_code(n), param_loc=loc,
                            file_name=self.analyzer.fig_step.get_belong_file(n)
                    ), self.analyzer
            )
        except:
            pass

    def _anchor_function_analysis(self, node: py2neo.Node, TAINT_DYNAMIC_CALL_FLAG: bool = None) -> int:
        if node[NODE_TYPE] in {TYPE_ECHO, TYPE_PRINT}:
            nn = self.analyzer.ast_step.filter_child_nodes(_node=node, node_type_filter=VAR_TYPES_EXCLUDE_CONST_VAR | SET_FUNCTION_CALL)
            if nn.__len__() >= 1:
                return 0b10, 10
            else:
                return 0b00, -1
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in \
                {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE, FLAG_EXEC_REQUIRE_ONCE}:
            return 0b10, 7
        elif node[NODE_TYPE] in {TYPE_INCLUDE_OR_EVAL} \
                and node[NODE_FLAGS][-1] in {FLAG_EXEC_EVAL}:
            return 0b10, 4
        code = self.analyzer.code_step.get_node_code(node)
        for vuln_type, anchor_functions in FUNCTION_MODEL.items():
            if code in anchor_functions:
                if code == "fopen" and vuln_type == 2:
                    self.f_insert(node, 12)
                    self.f_insert(node, 6)
                return 0b10, vuln_type
        if code in PHP_BUILT_IN_FUNCTIONS and node[NODE_TYPE] == TYPE_CALL:
            return 0b00, -1
        if node[NODE_TYPE] in {TYPE_STATIC_CALL, TYPE_CALL, TYPE_METHOD_CALL}:
            if self.analyzer.cg_step.find_decl_nodes(node):
                return 0b01, -1
            else:
                return 0b00, -1
        return 0b00, -1
    
    def load_sinks(self):
        if os.path.exists(self.sink_storage_path):
            with open(self.sink_storage_path, "r") as f:
                sink_storage = json.load(f)

            for vuln_type, sink_list in sink_storage.items():
                for node_dict in sink_list:
                    node = self.analyzer.get_node_itself(node_dict['id'])
                    self.potential_sinks[vuln_type].add_without_check(
                        AnchorNode.from_node_instance(
                            node, judge_type=node_dict['judge_type'], param_loc=node_dict['loc'],
                            git_repository=self.git_repository,
                            func_name=self.analyzer.code_step.get_node_code(node), 
                            file_name=self.analyzer.fig_step.get_belong_file(node)
                        )
                    )
            return True
        else:
            return False

    def store_sinks(self):
        sink_storage = {}
        for vuln_type in self.potential_sinks:
            if self.potential_sinks[vuln_type]:
                sink_storage[vuln_type] = [
                            {"id": i.node_id, "judge_type": i.judge_type, "loc": i.param_loc[-1]} 
                             for i in self.potential_anchor_nodes[vuln_type]]
        if sink_storage:
            with open(self.sink_storage_path, "w") as f:
                json.dump(obj=sink_storage, fp=f)

    def run(self) -> bool:
        query = f"MATCH (n:AST) WHERE n.type in {COMMON_NODE_TYPES.__str__()} RETURN n"
        nodes_todo_analysis = [node for node, in self.analyzer.basic_step.run(query)]
        for node_todo_analysis in nodes_todo_analysis:
            flag, vuln_type = self._anchor_function_analysis(node_todo_analysis, )
            if flag == 0b00:
                continue
            elif flag == 0b10:
                self.f_insert(node_todo_analysis, vuln_type)
            elif flag == 0b01:
                pass
