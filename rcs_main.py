import json
import os
import copy
import time
import traceback
import sys
import logging
from typing import List
from datetime import datetime

from config import STORAGE_PATH, DATABASE_PATH, RESULT_PATH, GIT_URL_DICT
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

def store_result(result: List[dict], base_dir: str, filename: str):
    path = os.path.join(base_dir, filename)
    if result:
        with open(path, "w") as f:
            json.dump(fp=f, obj=result)
    elif os.path.exists(path):
        os.remove(path)
        
def main():
    if len(sys.argv) < 2:
        logger.info("[-] Usage: python rcs_main.py <target>")
        logger.info("Exiting...")
        return
    target = sys.argv[1]

    start_databases(target)
    try:
        logger.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [*] Start analyzing {target}")
        
        if run(target):
            logger.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} The target {target} is vulnerable")
        else:
            logger.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} The target {target} is not vulnerable")
    except:
        logger.info(traceback.format_exc())
    finally:
        stop_databases(target)

def run(target) -> bool:
    analyzer_target = Neo4jEngine.from_dict(
            Neo4jConnectorCenter.from_map(target)
    )

    sink_finder = TargetSinkFinder(analysis_framework=analyzer_target, git_repository=target)
    sink_finder.run()
    potential_sink_dict = sink_finder.potential_sinks
    with open(os.path.join(STORAGE_PATH, 'signature_database.json')) as f:
        signature_database = json.load(f)

    result_storage_path = os.path.join(RESULT_PATH, target)
    is_vulnerable = False
    for vuln_type in VULN_TYPE_DICT.keys():
        signatures_to_match = signature_database[vuln_type]
        vuln_result = []
        signature_matcher = SignatureMatcher()
        potential_sink_list = potential_sink_dict[vuln_type]
        for potential_sink in potential_sink_list:
            context_slicer = ContextSlicer(
                    anchor_node=potential_sink,
                    analyzer=analyzer_target
            )
            context_series = context_slicer.run()
            for path, condition_ids in context_series:
                context = get_expression_and_conditions(analyzer_target, path, condition_ids)
                for cve_id, signature in signatures_to_match.items():
                    if signature_matcher.run_with_context(context, signature):
                        vuln_result.append(path)
                        is_vulnerable = True
        storage_filename = f"{VULN_TYPE_DICT[vuln_type]}.json"
        store_result(vuln_result, result_storage_path, storage_filename)
    return is_vulnerable

if __name__ == '__main__':
    main()
