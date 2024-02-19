import logging
import Levenshtein
import json
import os
from typing import List

from config import STORAGE_PATH
from core.helper import StringMatcher

logger = logging.getLogger(__name__)

class SignatureMatcher(object):
    def __init__(self, threshold: float=0.95):
        self.threshold = threshold
    
    def run_with_context(self, context, signature) -> List[str]:
        arg_expressions, conditions = context
        expression_list = signature['expression_list']
        safe_conditions = signature['safe_conditions']

        for _arg_expressions in expression_list:
            if len(_arg_expressions) != len(arg_expressions): 
                continue
            flag = 0
            for arg_expression, _arg_expression in zip(arg_expressions, _arg_expressions):
                similarity_score = Levenshtein.jaro(arg_expression, _arg_expression)
                if similarity_score >= self.threshold:
                    flag |= (1 << (arg_expressions.index(arg_expression)))

            if flag == 1 << len(arg_expressions) - 1: 
                return not self.check_safe_conditions(conditions, safe_conditions)
        return False
    
    def check_safe_conditions(self, conditions: List[str], safe_conditions: List[str]) -> bool:
        if not safe_conditions:
            return False
        for condition in conditions:
            if condition in safe_conditions:
                return True
        return False
