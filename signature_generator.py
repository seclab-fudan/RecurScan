import json
import os
import copy
import time
import traceback
import sys
import logging
from typing import List
from datetime import datetime

from config import DATA_INPUT_PATH, DATABASE_PATH, STORAGE_PATH, GIT_URL_DICT
from core.patch_analyzer import PatchAnalyzer
from core.cve_sink_finder import CVESinkFinder
from core.anchor_node_matcher import AnchorNodeMatcher
from core.target_sink_finder import TargetSinkFinder
from core.context_slicer import ContextSlicer
from core.neo4j_connector_center import Neo4jConnectorCenter
from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from core.signature_matcher import SignatureMatcher
from core.helper import get_expression_and_conditions, StringFilter

logger = logging.getLogger(__name__)

VULN_TYPE_DICT = {
    7: 'File Include',
    2: 'File Read',
    1: 'File Delete',
    12: 'File Write',
    10: 'XSS',
    4: 'Command Injection',
    3: 'Code Injection',
    6: 'File Upload',
    13: 'Open Redirect',
    8: 'PHP Object Injection',
    9: 'SQL Injection'
}

def start_databases(**kargs):
    for connector_name in kargs:
        logger.info(f"Starting {connector_name}...")
        io = os.popen(f"{DATABASE_PATH}/{connector_name}/bin/neo4j start").read()
        time.sleep(10)
        io = os.popen(
            f"tail -n 10 {DATABASE_PATH}/{connector_name}/logs/neo4j.log"
        ).read()
        print(io, flush=True)

    logger.info("Waiting for 30s to make sure neo4j opened...")
    for i in range(0, 10):
        time.sleep(3)

def stop_databases(**kargs):
    for connector_name in kargs:
        io = os.popen(f"{DATABASE_PATH}/{connector_name}/bin/neo4j stop").read()

def store_signatures(expression_list, safe_conditions, vuln_type, cve_id):
    path = os.path.join(STORAGE_PATH, 'signature_database.json')
    storage_obj = dict()
    if os.path.exists(path):
        with open(path) as f:
            storage_obj = json.load(f)

    if vuln_type not in storage_obj:
        storage_obj[vuln_type] = dict()
    storage_obj[vuln_type][cve_id] = {
        'expression_list': expression_list,
        'safe_conditions': safe_conditions
    }

    with open(path, 'w') as f:
        json.dump(fp=f, obj=storage_obj, indent=2)
        
def main():
    logger.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [*] Start generating signatures")
    cve_collection = json.load(fp=open(os.path.join(DATA_INPUT_PATH, "cve.json"), 'r', encoding='utf-8'))

    for cve_id, cve_dict in cve_collection.items():
        cve_repo = cve_dict['repo_name']
        vuln_type = cve_dict['vuln_type']
        commit_id = cve_dict['fixing_commit']
        _map_key_1 = f"{cve_repo}-{commit_id}_prepatch"
        _map_key_2 = f"{cve_repo}-{commit_id}_postpatch"

        start_databases(_map_key_1, _map_key_2)
        try:
            expression_list, safe_conditions = run_with_cve(_map_key_1=_map_key_1,
                                        _map_key_2=_map_key_2,
                                        vuln_type=vuln_type,
                                        cve_id=cve_id)
            store_signatures(expression_list, safe_conditions, vuln_type, cve_id)
        except:
            logger.info(traceback.format_exc())
        finally:
            stop_databases(_map_key_1, _map_key_2)
    logger.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} Signature database construction finished")

def run_with_cve(_map_key_1, _map_key_2, vuln_type: int, cve_id):
    git_repository, __ = StringFilter.filter_map_key_to_git_repository_and_version(_map_key_1)
    commit_id = StringFilter.filter_normalized_commit_id(__)
    
    analyzer_pre = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(_map_key_1)
    )
    analyzer_post = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(_map_key_2)
    )

    patch_analyzer = PatchAnalyzer(analyzer_pre, analyzer_post,
                                   commit_url=GIT_URL_DICT[git_repository] + '/commit/' + commit_id,
                                   commit_id=commit_id, cve_id=cve_id)
    patch_analyzer.run_result()
    default_config_level, is_find_flag = 0, False
    anchor_node_list = []
    while not is_find_flag:
        potential_anchor_finder = CVESinkFinder(analyzer_pre,
                                               commit_id=commit_id,
                                               vuln_type=vuln_type,
                                               git_repository=git_repository,
                                               config_level=default_config_level,
                                               cve_id=cve_id)
        is_find_flag = potential_anchor_finder.traversal()
        if not is_find_flag:
            default_config_level += 1
        anchor_node_list = potential_anchor_finder.potential_anchor_nodes

    if not anchor_node_list:
        return 0
    
    expression_list = []
    safe_conditions = []
    for anchor_node in anchor_node_list:
        anchor_node_matcher = AnchorNodeMatcher(
            high_version_node=anchor_node,
            high_version_analyzer=analyzer_pre,
            low_version_analyzer=analyzer_post,
            high_version_prefix=_map_key_1,
            low_version_prefix=_map_key_2,
        )
        anchor_node_ast = analyzer_pre.get_node_itself(anchor_node.node_id)
        postpatch_anchors, reason = anchor_node_matcher.run(
                                        node_type=anchor_node_ast[NODE_TYPE])
        postpatch_expression_list = []
        postpatch_condition_list = []

        signature_generator = ContextSlicer(anchor_node=copy.deepcopy(anchor_node), analyzer=analyzer_post)
        for potential_anchor in postpatch_anchors:
            signature_generator.clear_cache()
            signature_generator.anchor_node.node_id = potential_anchor[NODE_INDEX]
            signature_generator.anchor_node.get_more_info(signature_generator.analyzer)
            signature_series = signature_generator.run()
            for path, condition_ids in signature_series:
                arg_expressions, conditions = get_expression_and_conditions(analyzer_post, path, condition_ids)
                postpatch_expression_list.append(arg_expressions)
                postpatch_condition_list.extend(conditions)
        
        signature_generator = ContextSlicer(anchor_node=anchor_node, analyzer=analyzer_pre)
        signature_series = signature_generator.run()
        for path, condition_ids in signature_series:
            arg_expressions, conditions = get_expression_and_conditions(analyzer_pre, path, condition_ids)
            if arg_expressions not in postpatch_expression_list:
                expression_list.append(arg_expressions)
            postpatch_condition_list = [c for c in postpatch_condition_list if c not in conditions]
        safe_conditions.extend(postpatch_condition_list)
    return expression_list, safe_conditions

if __name__ == '__main__':
    main()
