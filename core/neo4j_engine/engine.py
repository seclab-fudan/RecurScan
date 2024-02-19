import copy
import re
from urllib.parse import urlparse

from .steps import *

logger = logging.getLogger(__name__)
MAX_CACHE_SIZE = 128


class Neo4jEngine(object):
    @classmethod
    def from_dict(cls, input_dict, use_cache=False):
        assert "NEO4J_HOST" in input_dict.keys()
        assert "NEO4J_USERNAME" in input_dict.keys()
        assert "NEO4J_PASSWORD" in input_dict.keys()
        assert "NEO4J_PORT" in input_dict.keys()
        assert "NEO4J_PROTOCOL" in input_dict.keys()
        assert "NEO4J_DATABASE" in input_dict.keys()
        return cls(input_dict, use_cache=use_cache)

    def clear_cache(self):
        pass

    def __init__(self, _graph=None, use_cache=False):
        self.__py2neo_version = py2neo.__version__
        self.graph_map = None
        self.neo4j_graph = None
        if isinstance(_graph, py2neo.Graph):
            __graph_instance = urlparse(re.findall(r'Graph\(\'(.*?)\'\)', _graph.__str__())[0])
            self.graph_map = {
                    "NEO4J_HOST": __graph_instance.hostname,
                    "NEO4J_USERNAME": __graph_instance.username,
                    "NEO4J_PASSWORD": __graph_instance.password,
                    "NEO4J_PORT": __graph_instance.port,
                    "NEO4J_PROTOCOL": __graph_instance.scheme,
                    "NEO4J_DATABASE": 'neo4j',
            }
            self.neo4j_graph = copy.deepcopy(_graph)
        else:
            self.graph_map = _graph
            try:
                self.neo4j_graph = py2neo.Graph(f"{self.graph_map['NEO4J_PROTOCOL']}://"
                                                f"{self.graph_map['NEO4J_HOST']}:{self.graph_map['NEO4J_PORT']}",
                                                user=self.graph_map['NEO4J_USERNAME'].__str__(),
                                                password=self.graph_map['NEO4J_PASSWORD'].__str__())
            except Exception as e:
                logger.fatal(e)
        assert self.neo4j_graph is not None, \
            "[-] init neo4j connection error , please check whether neo4j database has been opened "
        assert self.graph_map is not None, \
            "[*] back up for graph map , if met NotImplement Error ; Restart Map for recomputing"
        self._use_cache = False
        self.ast_step = ASTStep(self)
        self.pdg_step = PDGStep(self)
        self.cfg_step = CFGStep(self)
        self.cg_step = CGStep(self)
        self.chg_step = CHGStep(self)
        self.fig_step = FIGStep(self)
        self.code_step = CodeStep(self)
        self.basic_step = BasicStep(self)
        self.range_step = RangeStep(self)

    def __register_step(self, step_clazz: AbstractStep):
        assert isinstance(step_clazz, AbstractStep), "step_clazz must be abstract_step Impl"
        setattr(self, step_clazz.step_name, step_clazz)

    def run(self, query) -> py2neo.NodeMatch:
        return self.basic_step.run(query)

    def run_and_fetch_one(self, query) -> py2neo.NodeMatch:
        return self.basic_step.run_and_fetch_one(query)

    def match(self, *args, **kwargs) -> py2neo.NodeMatch:
        return self.basic_step.match(*args, **kwargs)

    def match_first(self, *args, **kwargs) -> py2neo.Node:
        return self.basic_step.match_first(*args, **kwargs)

    def match_relationship(self, *args, **kwargs) -> py2neo.RelationshipMatch:
        return self.basic_step.match_relationship(*args, **kwargs)

    def match_first_relationship(self, *args, **kwargs) -> py2neo.Relationship:
        return self.basic_step.match_first_relationship(*args, **kwargs)

    def get_node_itself(self, _id: int) -> py2neo.Node:
        return self.basic_step.get_node_itself(_id)

    def get_node_itself_by_identity(self, _id: int):
        return self.basic_step.get_node_itself_by_identity(_id)

    def get_ast_node_code(self, _node: py2neo.Node) -> str:
        return self.code_step.get_node_code(_node)

    def find_variables(self, _node: py2neo.Node, target_type: Union[List, Set] = None) -> List[str]:
        return self.code_step.find_variables(_node, target_type)

    def find_ast_parent_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.ast_step.find_parent_nodes(_node)

    def find_ast_child_nodes(self, _node: py2neo.Node, include_type: List[str] = None) -> List[py2neo.Node]:
        return self.ast_step.find_child_nodes(_node, include_type)

    def get_ast_ith_parent_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node or None:
        return self.ast_step.get_ith_parent_node(_node, i, ignore_error_flag)

    def get_ast_parent_node(self, _node: py2neo.Node, ignore_error_flag=False) -> Union[py2neo.Node, None]:
        return self.ast_step.get_ith_parent_node(_node, ignore_error_flag=ignore_error_flag)

    def get_ast_child_node(self, _node: py2neo.Node, ignore_error_flag=False) -> py2neo.Node:
        return self.ast_step.get_child_node(_node, ignore_error_flag)

    def get_ast_ith_child_node(self, _node: py2neo.Node, i: int = 0, ignore_error_flag=False) -> py2neo.Node or None:
        return self.ast_step.get_ith_child_node(_node, i, ignore_error_flag)

    def filter_ast_child_nodes(self, _node: py2neo.Node, max_depth=20, not_include_self: bool = False,
                               node_type_filter: Union[List[str], str, Set[str]] = None) -> List[py2neo.Node]:
        return self.ast_step.filter_child_nodes(_node, max_depth, not_include_self, node_type_filter)

    def get_ast_root_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.ast_step.get_root_node(_node)

    def get_control_node_condition(self, _node: py2neo.Node, ignore_error=False) -> py2neo.Node:
        return self.ast_step.get_control_node_condition(_node, ignore_error)

    def find_cfg_predecessors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cfg_step.find_successors(_node)

    def find_cfg_successors(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cfg_step.find_successors(_node)

    def get_cfg_flow_label(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return self.cfg_step.get_flow_label(_node_start, _node_end)

    def has_cfg(self, node):
        return self.match_relationship({node}, r_type=CFG_EDGE).exists()

    def find_pdg_use_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.pdg_step.find_use_nodes(_node)

    def find_pdg_def_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.pdg_step.find_def_nodes(_node)

    def get_pdg_vars(self, _node_start: py2neo.Node, _node_end: py2neo.Node) -> List[str]:
        return self.pdg_step.get_related_vars(_node_start, _node_end)

    def find_cg_call_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cg_step.find_call_nodes(_node)

    def find_cg_decl_nodes(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.cg_step.find_decl_nodes(_node)

    def find_fig_include_src(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.fig_step.find_include_src(_node)

    def find_fig_include_dst(self, _node: py2neo.Node) -> List[py2neo.Node]:
        return self.fig_step.find_include_dst(_node)

    def get_fig_include_map(self, _node: py2neo.Node) -> nx.DiGraph:
        return self.fig_step.get_include_map(_node)

    def get_fig_belong_file(self, _node: py2neo.Node) -> str:
        return self.fig_step.get_belong_file(_node)

    def get_fig_file_name_node(self, _file_name: str, match_strategy=1) -> Union[py2neo.Node, None]:
        return self.fig_step.get_file_name_node(_file_name, match_strategy)

    def get_fig_filesystem_node(self, _node: py2neo.Node) -> py2neo.Node:
        return self.fig_step.get_filesystem_node(_node)
