from typing import List, Union
import re
import py2neo

from core.neo4j_engine import Neo4jEngine
from .symbolic_tracking import SymbolicTracking


class Ast2CodeFactory(object):
    @staticmethod
    def extract_code(analyzer: Neo4jEngine, feeder: Union[List, int, py2neo.Node], with_memory=True, normalize_level=0):
        if isinstance(feeder, List) and feeder.__len__() == 0:
            return []
        st = SymbolicTracking(analyzer)
        if isinstance(feeder, List) and isinstance(feeder[0], int):
            res = []
            for node_id in feeder:
                _res = st.extract_code(analyzer.get_node_itself(node_id), normalize_level=normalize_level)
                if not with_memory:
                    st.clear_memory()
                if _res != "":
                    res.append(_res)
            if normalize_level >= 2 and res:
                res[-1] = re.sub(r"(\$[a-zA-Z0-9_]+)\s*(->[a-zA-Z0-9_]+)([^a-zA-Z0-9_])", 
                            Ast2CodeFactory.repl_chained_var, res[-1])
                res[-1] = re.sub(r"(\$[a-zA-Z0-9_]+)\s*(\[['\"].*?['\"]\])?", 
                            Ast2CodeFactory.repl_var, res[-1])
            return res
        elif isinstance(feeder, List) and isinstance(feeder[0], py2neo.Node):
            res = []
            for node_ast in feeder:
                _res = st.extract_code(node_ast, normalize_level=normalize_level)
                if not with_memory:
                    st.clear_memory()
                if _res != "":
                    res.append(_res)
            if normalize_level >= 2 and res:
                res[-1] = re.sub(r"(\$[a-zA-Z0-9_]+)\s*(->[a-zA-Z0-9_]+)([^a-zA-Z0-9_])", 
                            Ast2CodeFactory.repl_chained_var, res[-1])
                res[-1] = re.sub(r"(\$[a-zA-Z0-9_]+)\s*(\[['\"].*?['\"]\])?", 
                            Ast2CodeFactory.repl_var, res[-1])
            return res
        elif isinstance(feeder, py2neo.Node):
            return st.extract_code(feeder, normalize_level=normalize_level)
        elif isinstance(feeder, int):
            return st.extract_code(analyzer.get_node_itself(feeder), normalize_level=normalize_level)
        
    @staticmethod
    def repl_chained_var(matchObj):
        temp = "$Var"
        temp += "->Var" if matchObj.group(3) != "(" else matchObj.group(2)
        return temp + matchObj.group(3)
    
    @staticmethod
    def repl_var(matchObj):
        return "$Var" if matchObj.group(1) not in {"$Global", "$Source"} \
            else matchObj.group(0)
