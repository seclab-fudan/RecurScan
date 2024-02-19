import logging

import networkx as nx
import py2neo
from typing import List

from core.anchor_node import AnchorNode
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.ast2code import Ast2CodeFactory

logger = logging.getLogger(__name__)

class ContextSlicer(object):
    def __init__(self, anchor_node: AnchorNode, analyzer: Neo4jEngine, commit_id=None):
        self.analyzer = analyzer
        self.anchor_node = anchor_node
        self.commit_id = commit_id if commit_id is not None else 'uk'
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.taint_param = set()
        self.__backup_anchor_node_id = -1

    def clear_cache(self):
        self.anchor_node_ast = None
        self.anchor_node_root = None
        self.far_node = None
        self.pdg_digraph = nx.DiGraph()
        self.sources = set()
        self.taint_param = set()

    def run(self):
        self.context_series = list()
        self.do_backward_slice()
        self.do_forward_path_exploration()
        self.anchor_node.node_id = self.__backup_anchor_node_id
        return self.context_series

    def do_backward_slice(self):
        self.__backup_anchor_node_id = self.anchor_node.node_id

        taint_param = set()
        if self.anchor_node_ast is None:
            self.anchor_node_ast = self.analyzer.get_node_itself(self.anchor_node.node_id)
        if self.anchor_node_root is None:
            self.anchor_node_root = self.analyzer.ast_step.get_root_node(self.anchor_node_ast)
        self._do_backward_slice(self.anchor_node_ast, pdg_parent=None, id_threshold=self.anchor_node_ast[NODE_INDEX],
                                taint_param=taint_param)
        self.far_node = min(self.pdg_digraph.nodes.keys())
        self.taint_param = taint_param

    def _do_backward_slice(self, node, pdg_parent=None, id_threshold=0xff, taint_param: set = None):
        if node is None:
            return None
        if node[NODE_INDEX] > id_threshold:
            return None
        
        if not self.analyzer.cfg_step.has_cfg(node):
            node = self.analyzer.ast_step.get_root_node(node)
            if node[NODE_TYPE] in {TYPE_IF, TYPE_IF_ELEM, TYPE_WHILE, TYPE_DO_WHILE}:
                node = self.analyzer.get_control_node_condition(node)

        self.pdg_digraph.add_node(
                node[NODE_INDEX], add_rels="PDG", root_node_id=node[NODE_INDEX], lineno=node[NODE_LINENO],
        )
        if self.analyzer.ast_step.find_sources(node):
            self.sources.add(node[NODE_INDEX])
        
        if pdg_parent is not None:
            assert taint_param is not None
            if self.pdg_digraph.has_edge(node[NODE_INDEX], pdg_parent[NODE_INDEX]):
                return
            else:
                self.pdg_digraph.add_edge(
                    node[NODE_INDEX], pdg_parent[NODE_INDEX], add_rels='PDG', tant_param=taint_param
                )

        def_nodes = self.analyzer.pdg_step.find_def_nodes(node)
        if node in def_nodes:
            def_nodes.pop(def_nodes.index(node))
        
        for def_node in def_nodes:
            if def_node is None or def_node[NODE_INDEX] > id_threshold: continue
            var = self.analyzer.neo4j_graph.relationships.match([def_node, node],
                                                                r_type=DATA_FLOW_EDGE).first()['var']
            taint_param.add('$' + var)
            self._do_backward_slice(def_node, pdg_parent=node, id_threshold=def_node[NODE_INDEX], 
                                taint_param=taint_param)

    def do_forward_path_exploration(self):
        potential_condition_nodes = [i for i, in self.analyzer.run(
            "MATCH (A:AST) - [:PARENT_OF] -> (B:AST) WHERE A.type='AST_IF_ELEM' AND B.childnum=0 " + \
            f"AND B.type <> 'NULL' AND {self.far_node - 100} <= B.id <= {self.far_node} RETURN B"
        )]
        condition_ids = set()
        for node in potential_condition_nodes:
            parent_node = self.analyzer.get_ast_parent_node(node)
            low_bound, high_bound = self.analyzer.range_step.get_condition_range(parent_node)
            if low_bound <= self.far_node and self.far_node <= high_bound and \
                    self.analyzer.ast_step.find_sources(node):
                condition_ids.add(node[NODE_INDEX])
        
        far_node_ast = self.analyzer.get_node_itself(self.far_node)

        if self.anchor_node_root[NODE_INDEX] == far_node_ast[NODE_INDEX]:
            self.context_series.append(([self.anchor_node.node_id], sorted(condition_ids)))
            return

        self._do_forward_path_exploration(node=far_node_ast, cfg_pdg_path=set(), path_conditions=condition_ids,  
                                          threshold=[far_node_ast[NODE_INDEX], self.anchor_node_ast[NODE_INDEX]],
                                          cycle_exit_identifier=set())

    def _do_forward_path_exploration(self, node: py2neo.Node, cfg_pdg_path: set = set(), path_conditions: set = set(),
                                     has_source=False, threshold=None, cycle_exit_identifier: set = None, **kwargs):
        if cycle_exit_identifier is None:
            cycle_exit_identifier = {(-0xcaff, -0xcaff)}
        if threshold is None:
            threshold = [-0xff, 0xffff]
        threshold_bottom, threshold_upper = threshold

        if node is None or node.labels.__str__() != ":" + LABEL_AST:
            return None
        if node[NODE_INDEX] < threshold_bottom or node[NODE_INDEX] > threshold_upper:
            return None
        
        node = self._find_outside_exit_identifier(cycle_exit_identifier, node)
        if node[NODE_LINENO] is None:
            return None

        if node[NODE_INDEX] in self.pdg_digraph.nodes.keys():
            cfg_pdg_path.add(node[NODE_INDEX])
            if node[NODE_INDEX] in self.sources:
                has_source = True

        if node[NODE_INDEX] >= self.anchor_node_root[NODE_INDEX]:
            if self.anchor_node_root[NODE_INDEX] in cfg_pdg_path and \
                has_source:
                path_to_add = sorted(cfg_pdg_path)
                path_to_add[-1] = self.anchor_node_ast[NODE_INDEX]
                conditions_to_add = sorted(path_conditions)
                if (path_to_add, conditions_to_add) not in self.context_series:
                    self.context_series.append((path_to_add, conditions_to_add))
            return None

        parent_node = self.analyzer.ast_step.get_parent_node(node)
        if parent_node[NODE_TYPE] in {TYPE_WHILE}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                source_rels = [i for i, in self.analyzer.run(
                    f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                    f"AND C.id={node[NODE_INDEX]} RETURN P"
                )]
                if source_rels or self.analyzer.ast_step.find_sources(node):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[1].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_IF_ELEM} and node[NODE_CHILDNUM] == 0:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                source_rels = [i for i, in self.analyzer.run(
                    f"MATCH P = (S:AST) - [:REACHES*1..] -> (C:AST) WHERE S.id in {list(self.sources).__str__()} " + \
                    f"AND C.id={node[NODE_INDEX]} RETURN P"
                )]
                if source_rels or self.analyzer.ast_step.find_sources(node):
                    path_conditions.add(node[NODE_INDEX])
                cfg_rel_true, cfg_rel_false = cfg_rels
                self._do_forward_path_exploration(
                        node=cfg_rel_true.end_node, parent_cfg_node=cfg_rel_true.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_true['flowLabel']},
                )
                if node[NODE_INDEX] in path_conditions:
                    path_conditions.remove(node[NODE_INDEX])
                self._do_forward_path_exploration(
                        node=cfg_rel_false.end_node, parent_cfg_node=cfg_rel_false.start_node,
                        cfg_pdg_path=cfg_pdg_path, cycle_exit_identifier=cycle_exit_identifier,
                        path_conditions=path_conditions, has_source=has_source,
                        threshold=[-1, threshold_upper], edge_property={"flowLabel": cfg_rel_false['flowLabel']},
                )
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_FOR} and node[NODE_CHILDNUM] == 1:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                cfg_rel = cfg_rels[0]
                cycle_exit_identifier.add(
                        (self.analyzer.ast_step.get_ith_child_node(parent_node, i=2), cfg_rels[1].end_node))

                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif node[NODE_TYPE] in {TYPE_FOREACH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels.__len__() == 2:
                if cfg_rels[0]['flowLabel'] == 'complete':
                    complete_index, next_index = 0, 1
                else:
                    complete_index, next_index = 1, 0
                cfg_rel = cfg_rels[next_index]
                cycle_exit_identifier.add((cfg_rel.start_node, cfg_rels[complete_index].end_node))
                self._do_forward_path_exploration(node=cfg_rel.end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rel.start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                pass
        elif parent_node[NODE_TYPE] in {TYPE_TRY}:
            pass
        elif parent_node[NODE_TYPE] in {TYPE_SWITCH}:
            cfg_rels = [i for i in self.analyzer.neo4j_graph.relationships.match([node], r_type=CFG_EDGE)]
            cfg_rels = list(sorted(cfg_rels, key=lambda x: x.end_node[NODE_INDEX]))
            if cfg_rels[-1][CFG_EDGE_FLOW_LABEL] == 'default':
                cfg_rels[-1][
                    CFG_EDGE_FLOW_LABEL] = f"! ( in_array( {TMP_PARAM_FOR_SWITCH},{[i['flowLabel'] for i in cfg_rels[:-2]]}) )"
            for index in range(cfg_rels.__len__()):
                self._do_forward_path_exploration(node=cfg_rels[index].end_node, cfg_pdg_path=cfg_pdg_path,
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=cfg_rels[index].start_node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper],
                                                  edge_property={"flowLabel": f"\'{cfg_rels[index]['flowLabel']}\'"})
        else:
            cfg_next_node = self.analyzer.cfg_step.find_successors(node)
            if cfg_next_node.__len__() == 0:
                return
            cfg_next_node = cfg_next_node[-1]
            if node[NODE_TYPE] in {TYPE_EXIT}:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=None,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
            else:
                self._do_forward_path_exploration(node=cfg_next_node, cfg_pdg_path=cfg_pdg_path, 
                                                  path_conditions=path_conditions, has_source=has_source,
                                                  parent_cfg_node=node,
                                                  cycle_exit_identifier=cycle_exit_identifier,
                                                  threshold=[-1, threshold_upper])
        if node[NODE_INDEX] in cfg_pdg_path:
            cfg_pdg_path.remove(node[NODE_INDEX])
        if node[NODE_INDEX] in path_conditions:
            path_conditions.remove(node[NODE_INDEX])

    def _find_outside_exit_identifier(self, cycle_exit_identifier, input_node):
        for _cycle_exit_identifier in cycle_exit_identifier:
            if input_node == _cycle_exit_identifier[0]:
                input_node = self._find_outside_exit_identifier(cycle_exit_identifier, _cycle_exit_identifier[1])
        return input_node
        