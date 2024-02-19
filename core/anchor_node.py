import logging
from abc import ABC, ABCMeta, abstractmethod
from typing import List, Union

import py2neo

from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)


class BaseNode(object):
    node_id: int
    version: str
    git_repository: str
    func_name: str
    param_loc: List[int]
    file_name: str
    lineno: int

    __metaclass__ = ABCMeta

    def __init__(self, node_id=-1, version: str = '', git_repository: str = '', func_name="foo", param_loc=None,
                 file_name="index.php", lineno=0):
        if param_loc is None:
            param_loc = [0]
        if isinstance(param_loc, int):
            param_loc = [int(param_loc)]
        elif isinstance(param_loc, str):
            param_loc = [int(i) for i in param_loc.replace("[", "").replace("]", "").split("|")]
        self.lineno = lineno
        self.node_id = int(node_id)
        self.version = version
        self.git_repository = git_repository
        self.param_loc = param_loc
        self.func_name = func_name
        self.file_name = file_name

    def __hash__(self):
        return self.node_id.__hash__()

    def __eq__(self, other):
        if self.node_id == other.node_id:
            return True
        else:
            return False

    def __str__(self):
        return f"{self.git_repository}-{self.version} with node_id ::{self.node_id}"

    @abstractmethod
    def get_func_name(self, analyzer) -> str:
        pass

    @abstractmethod
    def get_file_name(self, analyzer) -> str:
        pass

    @abstractmethod
    def get_lineno(self, analyzer) -> str:
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, feeder: dict):
        return cls(**feeder)

    @classmethod
    @abstractmethod
    def from_id(cls, analyzer, id):
        return cls.from_dict(**{})

    def __ge__(self, other):
        return self.node_id >= other.node_id

    def __gt__(self, other):
        return self.node_id > other.node_id

    def __le__(self, other):
        return self.node_id <= other.node_id

    def __lt__(self, other):
        return self.node_id < other.node_id


class AnchorNode(BaseNode, ABC):
    node_id: int
    version: str
    git_repository: str
    func_name: str
    param_loc: List[int]
    file_name: str
    lineno: int
    prepatch_lineno: int
    judge_type: int
    cve_id: str

    @classmethod
    def from_node_instance(cls, node: py2neo.Node, **kwargs):
        return cls(**{
                "node_id": node[NODE_INDEX] if NODE_INDEX in node and node[NODE_INDEX] else node.identity,
                "version": kwargs.pop('version', "uk"),
                "git_repository": kwargs.pop('git_repository', "uk"),
                "func_name": kwargs.pop('func_name', "uk"),
                "param_loc": kwargs.pop('param_loc', -1),
                "file_name": kwargs.pop('file_name', "uk"),
                "lineno": node[NODE_LINENO] if NODE_LINENO in node and node[NODE_LINENO] else -1,
                "judge_type": kwargs.pop('judge_type', -1),
                "cve_id": node["cve_id"] if "cve_id" in node and node["cve_id"] else "CVE-0000-0000"
        })

    def __init__(self, cve_id="CVE-0000-0000", prepatch_lineno=0, judge_type=-1, **kwargs):
        super(AnchorNode, self).__init__(**kwargs)
        self.cve_id = cve_id
        self.prepatch_lineno = prepatch_lineno
        self.judge_type = judge_type

    @staticmethod
    def get_csv_header():
        return "node_id,version,git_repository,param_loc,func_name,file_name,cve_id,lineno,prepatch_lineno\n"

    def to_csv(self):
        return f"{self.node_id},{self.version},{self.git_repository}," \
               f"'{self.param_loc}',{self.func_name},{self.file_name},{self.cve_id},{self.lineno},{self.prepatch_lineno}\n"

    def get_func_name(self, analyzer: Neo4jEngine) -> str:
        self.func_name = analyzer.code_step.get_node_code(analyzer.get_node_itself(self.node_id))
        if "::" in self.func_name:
            self.func_name = self.func_name[self.func_name.index("::") + 2:]
        if "->" in self.func_name:
            self.func_name = self.func_name[self.func_name.index("->") + 2:]
        return self.func_name

    def get_file_name(self, analyzer: Neo4jEngine) -> str:
        self.file_name = analyzer.fig_step.get_belong_file(
                analyzer.get_node_itself(self.node_id))
        return self.file_name

    def get_lineno(self, analyzer: Neo4jEngine) -> int:
        self.lineno = analyzer.get_node_itself(self.node_id)['lineno']
        return self.lineno

    def get_node_id(self, analyzer: Neo4jEngine):
        top_file_node = analyzer.fig_step.get_file_name_node(self.file_name)
        if top_file_node is None:
            logger.warning(self.file_name + " not exists exit")
            return 0
        if self.func_name in {"echo", "print", "return", "include", "include_once", "require", "require_once", "eval",
                              "die", "exit", "unset", "isset"}:
            query = f"MATCH (A:AST) WHERE A.lineno = {self.lineno} "
            if self.func_name == "echo":
                query += f" and A.type = '{TYPE_ECHO}'"
            elif self.func_name == "print":
                query += f" and A.type = '{TYPE_PRINT}'"
            elif self.func_name == "die" or self.func_name == "exit":
                query += f" and A.type = '{TYPE_EXIT}'"
            elif self.func_name == "return":
                query += f" and A.type = '{TYPE_RETURN}'"
            elif self.func_name == 'isset':
                query += f" and A.type = '{TYPE_ISSET}'"
            elif self.func_name == 'unset':
                query += f" and A.type = '{TYPE_UNSET}'"
            elif self.func_name in {"include", "include_once", "require", "require_once", "eval", }:
                query += f" and A.type = '{TYPE_INCLUDE_OR_EVAL}'"
            query += f" and A.fileid = {top_file_node[NODE_FILEID]} "
            query += f" RETURN A "
            potential_nodes = []
            for node, in analyzer.basic_step.run(query):
                file_name = analyzer.fig_step.get_belong_file(analyzer.get_node_itself(node[NODE_INDEX]))
                if self.file_name in file_name:
                    potential_nodes.append(node)

            if potential_nodes.__len__() == 1:
                logger.info(f"LOCATE {self.__str__()}")
                self.node_id = potential_nodes[0][NODE_INDEX]
                return self.node_id
            elif potential_nodes.__len__() >= 2:
                if self.func_name == 'echo' or self.func_name == 'print':
                    logger.info("Trying to solve this problem with vars search")
                    _lock_index = []
                    _lock_vars = []
                    for index, potential_node in enumerate(potential_nodes):
                        var_len = analyzer.code_step.find_variables(
                                potential_node
                        ).__len__()
                        if var_len >= 1:
                            _lock_index.append(index)
                            _lock_vars.append(var_len)
                    if _lock_index.__len__() == 1:
                        logger.info("Problem solved")
                        self.node_id = potential_nodes[_lock_index[-1]][NODE_INDEX]
                    elif _lock_index.__len__() == 0:
                        logger.warning("no var searched ;STATEGY FAILED !!!")
                    elif _lock_index.__len__() >= 2:
                        self.node_id = potential_nodes[_lock_index[_lock_vars.index(max(_lock_vars))]][NODE_INDEX]
                        return potential_nodes
                else:
                    logger.warning("IT IS NOT ECHO, STATEGY FAILED !!!")
                    self.node_id = potential_nodes[0][NODE_INDEX]
                    return potential_nodes
            else:
                return
        else:
            if self.judge_type == 8 and self.func_name != "return":
                query = f"MATCH (A:AST) WHERE A.lineno = {self.lineno} and A.name = '{self.func_name}' and A.fileid = {top_file_node[NODE_FILEID]} RETURN A "
            else:
                query = f"MATCH (A:AST) WHERE A.lineno = {self.lineno} and A.code = '{self.func_name}' and A.fileid = {top_file_node[NODE_FILEID]} RETURN A "
            for node, in analyzer.basic_step.run(query):
                file_name = analyzer.fig_step.get_belong_file(analyzer.get_node_itself(node['id']))
                if self.file_name in file_name:
                    p_node = get_specify_parent_node(analyzer, node)
                    if p_node is None:
                        continue
                    self.node_id = p_node['id']
                    logger.info(f"LOCATE {self.__str__()}")
                    return self.node_id

    def get_more_info(self, analyzer):
        self.get_func_name(analyzer)
        self.get_file_name(analyzer)
        self.get_lineno(analyzer)

    def __str__(self) -> str:
        return f"{self.version}/{self.file_name}" \
               f"#L{self.lineno}  {self.func_name} node_id={self.node_id}"

    def __repr__(self) -> str:
        return f"{self.version}/{self.file_name}" \
               f"#L{self.lineno}  {self.func_name} node_id={self.node_id}"

    def __hash__(self):
        return self.node_id.__hash__()

    def __eq__(self, other):
        if self.node_id == other.node_id:
            return True
        else:
            return False


def get_specify_parent_node(analyzer: Neo4jEngine, _node: py2neo.Node,
                            specify_type: set = FUNCTION_CALL_TYPES | FUNCTION_DECLARE_TYPES) -> Union[
    py2neo.Node, None]:
    if _node[NODE_TYPE] in specify_type:
        return _node
    __node = analyzer.ast_step.get_parent_node(_node)
    if __node[NODE_TYPE] in specify_type:
        return __node
    elif __node[NODE_TYPE] in {TYPE_STMT_LIST}:
        logger.warning("get specify node error ,get EXIT specifier")
        return None
    else:
        return get_specify_parent_node(analyzer, __node, specify_type=specify_type)
