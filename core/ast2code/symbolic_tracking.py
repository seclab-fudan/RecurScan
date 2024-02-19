import logging
from html import unescape

import py2neo

from core.neo4j_engine import Neo4jEngine
from core.neo4j_engine.const import *
from .three_address_code_path import ThreeAddressCode, ThreeAddressCodePath

VULNERABLE_CALLS = {
    "file", "file_get_contents", "readfile", "fopen", "unlink", "rmdir", 
    "file_put_contents", "fwrite", "print_r", "exec", "passthru", "proc_open", 
    "system", "shell_exec", "popen", "pcntl_exec", 'create_function', 'assert', 
    'array_map', 'preg_replace', "copy", "move_uploaded_file", "rename", "header",
    "unserialize", "pg_query", "pg_send_query", "pg_prepare", "mysql_query", 
    "mysqli_prepare", "mysqli_query", "mysqli_real_query"
}
 
UNSAFE_SERVER_INFO = ["argv", "argc", "QUERY_STRING", "SCRIPT_NAME", 
                          "HTTP_ACCEPT", "HTTP_ACCEPT_CHARSET", "HTTP_ACCEPT_ENCODING", 
                          "HTTP_ACCEPT_LANGUAGE", "HTTP_CONNECTION", "HTTP_REFERER", 
                          "HTTP_USER_AGENT", "AUTH_TYPE", "PHP_AUTH_DIGEST", "PHP_AUTH_USER", 
                          "PHP_AUTH_PW", "PATH_INFO", "ORIG_PATH_INFO", "REQUEST_URI", 
                          "PHP_SELF", "PATH_TRANSLATED"]

def addslashes(s):
    if isinstance(s, str):
        d = {"\0": "",
             "\"": "\\\""}
        for x in d:
            s = s.replace(x, d.get(x))
        return unescape(s)
    elif s is None:
        return "NULL"
    else:
        return str(s)


def solve_type_conflict(type1, type2):
    assert type1 in ["", "string", "number", "boolean", ]
    assert type2 in ["", "string", "number", "boolean", ]

    if type1 == "":
        return type2
    if type2 == "":
        return type1
    if type1 == type2:
        return type1
    _type = {type1, type2}
    if _type == {"number", "boolean"}:
        return "number"
    if _type == {"number", "string"}:
        return "number"
    if _type == {"string", "boolean"}:
        return "boolean"


def join_var_node(identity: int, ADD_ENC_FLAG=False, tmp_var_name="$t_", enc_var_name="_enc") -> str:
    return (tmp_var_name + str(identity)) if not ADD_ENC_FLAG else (tmp_var_name + str(identity) + enc_var_name)


logger = logging.getLogger(__name__)


class SymbolicTracking(object):
    def __init__(self, analyzer: Neo4jEngine):
        self.tac_path = ThreeAddressCodePath()
        self.analyzer = analyzer
        self.__global_normalize_level = 0b00000000

    def to_src_code(self):
        return self.tac_path.to_src_code()

    def extract_code(self, node: py2neo.Node, normalize_level=0):
        if not node.has_label(LABEL_AST):
            return ""
        result = 0
        level_backup = self.__global_normalize_level
        self.__global_normalize_level = normalize_level
        a, b = self.manage_generic_node(node)
        c, d = self.tac_path.to_raw_code()
        if d == '':
            result = a
        else:
            result = d
        self.__global_normalize_level = level_backup
        return str(result)

    def get_expression_ith_node(self, ith: int) -> py2neo.Node:
        node = self.analyzer.match(
            code="_expr_{}".format(ith)
        ).first()
        return self.analyzer.get_ast_root_node(node)

    def get_condition_ith_node(self, ith: int) -> py2neo.Node:
        node = self.analyzer.match(
            code="_cond_{}".format(ith)
        ).first()
        return self.analyzer.get_ast_ith_child_node(
            self.analyzer.get_ast_root_node(node), 1
        )

    def clear_memory(self):
        self.tac_path = ThreeAddressCodePath()

    def get_node(self, _id, ):
        return self.analyzer.get_node_itself(_id)

    def gen_formula(self, left: str, right: list, op: str, node_type: str, node_id: int, ltype: str, rtype: list):
        self.tac_path.append(
            ThreeAddressCode(left, right, op, node_type, node_id, ltype, rtype)
        )
        return left, ltype

    def manage_basic_block(self, node: py2neo.Node):
        if node[NODE_TYPE] == TYPE_CALL:
            return self.manage_function_call(node)
        elif node[NODE_TYPE] == TYPE_STATIC_CALL:
            return self.manage_static_function_call(node)
        elif node[NODE_TYPE] == TYPE_METHOD_CALL:
            return self.manage_dynamic_function_call(node)
        elif node[NODE_TYPE] == TYPE_DIM:
            return self.manage_dim(node)
        elif node[NODE_TYPE] == TYPE_VAR:
            return self.manage_var(node)
        elif node[NODE_TYPE] == TYPE_STRING:
            return self.manage_constant_string(node)
        elif node[NODE_TYPE] == TYPE_INTEGER:
            return self.manage_constant_integer(node)
        elif node[NODE_TYPE] == TYPE_DOUBLE:
            return self.manage_constant_double(node)
        elif node[NODE_TYPE] == TYPE_CONST:
            return self.manage_generic_constant(node)
        elif node[NODE_TYPE] == TYPE_MAGIC_CONST:
            return self.manage_magic_constant(node)
        elif node[NODE_TYPE] == TYPE_NULL:
            return self.manage_null(node)
        elif node[NODE_TYPE] == TYPE_REF:
            return self.manage_ref(node)
        elif node[NODE_TYPE] == TYPE_CLASS_CONST:
            return self.manage_class_constant(node)
        elif node[NODE_TYPE] == TYPE_STATIC_PROP:
            return self.manage_type_static_prop(node)
        elif node[NODE_TYPE] == TYPE_PROP:
            return self.manage_type_prop(node)
        elif node[NODE_TYPE] == TYPE_ARRAY:
            return self.manage_type_array(node)
        elif node[NODE_TYPE] == TYPE_LIST:
            return self.manage_type_list(node)
        elif node[NODE_TYPE] == TYPE_ARRAY_ELEM:
            return self.manage_type_array_elem(node)
        elif node[NODE_TYPE] == TYPE_GLOBAL:
            return self.manage_global_node(node)

    def manage_global_node(self, node: py2neo.Node):
        return self.manage_generic_node(self.analyzer.get_ast_child_node(node))

    def manage_type_static_prop(self, node: py2neo.Node):
        class_code = self.analyzer.get_ast_child_node(self.analyzer.get_ast_child_node(node))[
            'code']
        expr_code = self.analyzer.get_ast_ith_child_node(node, 1)['code']
        return f"{class_code}::${expr_code}", "string"

    def manage_type_list(self, node: py2neo.Node):
        list_nodes = self.analyzer.find_ast_child_nodes(node)
        resolved_list_nodes = []
        resolved_list_nodes_types = []
        for list_node in list_nodes:
            assert isinstance(list_node, py2neo.Node)
            res_arg = self.manage_generic_node(list_node)
            resolved_list_nodes.append(res_arg[0])
            resolved_list_nodes_types.append(res_arg[1])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_list_nodes,
            op="array",
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="string",
            rtype=resolved_list_nodes_types
        )

    def manage_instanceof_operation(self, node: py2neo.Node):
        judge_instance_var, judge_instance_var_type = self.manage_generic_node(
            self.analyzer.find_ast_child_nodes(node)[0])

        instance_var, instance_type = \
            self.analyzer.find_ast_child_nodes(self.analyzer.find_ast_child_nodes(node)[1])[0][
                'code'], 'string'
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[judge_instance_var, instance_var],
            op=TYPE_INSTANCEOF,
            node_type=TYPE_BINARY_OP,
            node_id=node.identity,
            ltype="string",
            rtype=[judge_instance_var_type, instance_type]
        )

    def manage_new_operation(self, node: py2neo.Node):
        args = self.analyzer.ast_step.find_function_arg_node_list(node)
        name_node = self.analyzer.find_ast_child_nodes(node)[0]
        resolved_args = []
        resolved_args_types = []
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            res_arg = self.manage_generic_node(arg)
            resolved_args.append(res_arg[0])
            resolved_args_types.append(res_arg[1])
        expr, expr_type = self.gen_formula(
            left=join_var_node(name_node.identity),
            right=resolved_args,
            op=self.analyzer.find_ast_child_nodes(name_node)[0][NODE_CODE],
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="",
            rtype=resolved_args_types
        )
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr],
            op=TYPE_NEW,
            node_type=TYPE_UNARY_OP,
            node_id=node.identity,
            ltype="",
            rtype=[expr_type]
        )

    def manage_function_call(self, node: py2neo.Node):
        args = self.analyzer.ast_step.find_function_arg_node_list(node)
        resolved_args = []
        resolved_args_types = []
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            res_arg = self.manage_generic_node(arg)
            resolved_args.append(res_arg[0])
            resolved_args_types.append(res_arg[1])
        function_call_code = self.analyzer.code_step.get_ast_call_code(node)
        op = "Sink" if function_call_code in VULNERABLE_CALLS and \
            self.__global_normalize_level >= 2 else function_call_code
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_args,
            op=op,
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="string",
            rtype=resolved_args_types
        )

    def manage_exit_operation(self, node: py2neo.Node):
        if self.analyzer.find_ast_child_nodes(node).__len__() == 0:
            expr, expr_type = None, None
        else:
            expr, expr_type = self.manage_generic_node(
                self.analyzer.find_ast_child_nodes(node)[0]
            )
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr] if expr is not None else [],
            op="die",
            node_id=node.identity,
            node_type=TYPE_CALL,
            ltype="boolean",
            rtype=[expr_type] if expr_type is not None else [],
        )

    def manage_empty_operation(self, node: py2neo.Node):
        condition = self.manage_generic_node(
            self.analyzer.find_ast_child_nodes(node)[0]
        )
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[condition[0]],
            op="empty",
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="boolean",
            rtype=[condition[1]]
        )

    def manage_var(self, node: py2neo.Node):
        if self.__global_normalize_level >= 2 and \
                self.analyzer.code_step.get_ast_var_code(node) in \
                {"$_POST", "$_GET", "$_REQUEST", "$_FILE", "$_COOKIE", "$_SERVER", "$GLOBALS"}:
            return "$Global" if self.analyzer.code_step.get_ast_var_code(node) == "$GLOBALS" else "$Source", ""
        if self.__global_normalize_level == 1:
            return "$var", ""
        return self.analyzer.code_step.get_ast_var_code(node), ""

    def manage_dim(self, node: py2neo.Node):
        nodes = self.analyzer.find_ast_child_nodes(node)
        if nodes[0]['type'] == TYPE_VAR and nodes[1]['type'] == TYPE_STRING:
            if self.__global_normalize_level >= 2: 
                if self.analyzer.code_step.get_ast_dim_body_code(node) in \
                        {"_POST", "_GET", "_REQUEST", "_FILE", "_COOKIE", "GLOBALS"}:
                    return "$Global" if self.analyzer.code_step.get_ast_dim_body_code(node) == "GLOBALS" else "$Source", ""
                elif self.analyzer.code_step.get_ast_dim_body_code(node) == "_SERVER" and \
                        self.analyzer.code_step.get_node_code(self.analyzer.ast_step.get_child_node(node)) in UNSAFE_SERVER_INFO:
                    return "$Source"
            if self.__global_normalize_level == 1:
                return "$var", ""
            return self.analyzer.code_step.get_ast_dim_code(node), ""
        else:
            if self.__global_normalize_level >= 2:
                if self.analyzer.code_step.get_ast_dim_body_code(node) in \
                        {"_POST", "_GET", "_REQUEST", "_FILE", "_COOKIE", "GLOBALS"}:
                    return "$Global" if self.analyzer.code_step.get_ast_dim_body_code(node) == "GLOBALS" else "$Source", ""
                elif self.analyzer.code_step.get_ast_dim_body_code(node) == "_SERVER":
                    if nodes[1][NODE_TYPE] == TYPE_NULL or \
                            (NODE_CODE in nodes[1].keys() and nodes[1][NODE_CODE] in UNSAFE_SERVER_INFO):
                        return "$Source"
            if self.__global_normalize_level == 1:
                return "$var", ""
            expr_var, expr_type = self.manage_generic_node(nodes[0])
            slice_var, slice_type = self.manage_generic_node(nodes[1])
            if slice_var == "null":
                return expr_var + '[]', ""
            else:
                return expr_var + '[' + str(slice_var) + ']', ""

    def manage_binary_operation(self, node: py2neo.Node):
        l_expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        r_expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[1])
        if node['flags'][0] in ["BINARY_CONCAT"]:
            return self.gen_formula(
                left=join_var_node(node.identity),
                right=[l_expr[0], r_expr[0]],
                op=node['flags'][0],
                node_type=node[NODE_TYPE],
                node_id=node.identity,
                ltype="string",
                rtype=['string', 'string']
            )

        elif (node['flags'][0] in [FLAG_BINARY_IS_SMALLER, FLAG_BINARY_IS_SMALLER_OR_EQUAL, FLAG_BINARY_IS_GREATER,
                                   FLAG_BINARY_IS_GREATER_OR_EQUAL]):
            return self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                    node[NODE_TYPE],
                                    node.identity, "boolean", ["number", "number"])
        elif node['flags'][0] in [FLAG_BINARY_BOOL_AND, FLAG_BINARY_BOOL_OR, FLAG_BINARY_BOOL_XOR,
                                  FLAG_BINARY_BITWISE_AND, FLAG_BINARY_BITWISE_XOR, FLAG_BINARY_BITWISE_OR]:
            return self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                    node[NODE_TYPE],
                                    node.identity, "boolean", ["boolean", "boolean"])
        elif node['flags'][0] in [FLAG_BINARY_ADD, FLAG_BINARY_SUB, FLAG_BINARY_MUL, FLAG_BINARY_DIV, FLAG_BINARY_MOD,
                                  FLAG_BINARY_POW, FLAG_BINARY_SHIFT_RIGHT, FLAG_BINARY_SHIFT_LEFT]:
            return self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                    node[NODE_TYPE],
                                    node.identity, "number", ["number", "number"])
        elif (node['flags'][0] in [FLAG_BINARY_EQUAL, FLAG_BINARY_NOT_EQUAL, FLAG_BINARY_IS_IDENTICAL,
                                   FLAG_BINARY_IS_NOT_IDENTICAL]):
            return self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                    node[NODE_TYPE],
                                    node.identity, "boolean",
                                    [solve_type_conflict(l_expr[1], r_expr[1]),
                                     solve_type_conflict(l_expr[1], r_expr[1])])

    def manage_generic_node(self, node: py2neo.Node):
        if node[NODE_TYPE] in {TYPE_CALL, TYPE_DIM, TYPE_VAR, TYPE_METHOD_CALL, TYPE_STATIC_CALL, TYPE_PROP, TYPE_ARRAY,
                               "string", "integer", "double", TYPE_CONST, TYPE_MAGIC_CONST, TYPE_STATIC_PROP,
                               TYPE_CLASS_CONST, TYPE_LIST, TYPE_GLOBAL,
                               TYPE_ARRAY_ELEM, TYPE_NULL, TYPE_REF}:
            return self.manage_basic_block(node)
        elif node[NODE_TYPE] in {TYPE_BINARY_OP}:
            return self.manage_binary_operation(node)
        elif node[NODE_TYPE] in {TYPE_UNARY_OP, TYPE_POST_INC, TYPE_POST_DEC, TYPE_PRE_INC, TYPE_PRE_DEC,
                                 TYPE_CAST}:
            return self.manage_unary_operation(node)
        elif node[NODE_TYPE] in {TYPE_CONDITIONAL}:
            return self.manage_condition_operation(node)
        elif node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_ASSIGN_REF, TYPE_ASSIGN_OP, TYPE_STATIC}:
            return self.manage_assignment_operation(node)
        elif node[NODE_TYPE] == TYPE_EXPR_LIST:
            return self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        elif node[NODE_TYPE] == TYPE_ENCAPS_LIST:
            return self.manage_encapsulated_list(node)

        elif node[NODE_TYPE] == TYPE_EXIT:
            return self.manage_exit_operation(node)
        elif node[NODE_TYPE] == TYPE_EMPTY:
            return self.manage_empty_operation(node)
        elif node[NODE_TYPE] == TYPE_ISSET:
            return self.manage_isset_operation(node)
        elif node[NODE_TYPE] == TYPE_UNSET:
            return self.manage_unset_operation(node)
        elif node[NODE_TYPE] in [TYPE_ECHO, TYPE_PRINT]:
            return self.manage_echo_operation(node)
        elif node[NODE_TYPE] == TYPE_INCLUDE_OR_EVAL and (
                set(node['flags']) & {FLAG_EXEC_INCLUDE, FLAG_EXEC_INCLUDE_ONCE, FLAG_EXEC_REQUIRE,
                                      FLAG_EXEC_REQUIRE_ONCE}):
            return self.manage_include_operation(node)
        elif node[NODE_TYPE] == TYPE_INCLUDE_OR_EVAL and (set(node['flags']) & {FLAG_EXEC_EVAL}):
            return self.manage_eval_operation(node)

        elif node[NODE_TYPE] == TYPE_NEW:
            return self.manage_new_operation(node)
        elif node[NODE_TYPE] == TYPE_INSTANCEOF:
            return self.manage_instanceof_operation(node)
        elif node[NODE_TYPE] == TYPE_RETURN:
            return self.manage_return_operation(node)

        elif node[NODE_TYPE] == TYPE_FOREACH:
            return self.manage_foreach_operation(node)
        elif node[NODE_TYPE] in {TYPE_BREAK, TYPE_PARAM, TYPE_CONTINUE}:
            if node[NODE_TYPE] == TYPE_BREAK:
                return "break", ""
            elif node[NODE_TYPE] == TYPE_PARAM:
                return self.manage_param_operation(node)
            elif node[NODE_TYPE] == TYPE_CONTINUE:
                return "continue", ""
        logger.warning("Get not support node type" + node.__str__())

        return '', ''

    def manage_param_operation(self, node: py2neo.Node):
        if self.analyzer.get_ast_ith_child_node(node, i=2)[NODE_TYPE] == TYPE_NULL:
            return '', ''
        else:
            var, var_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=1))
            value, value_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=2))
            return self.gen_formula(left=var, right=[value], ltype=var_type, rtype=[value_type], op=TYPE_ASSIGN,
                                    node_type=TYPE_ASSIGN, node_id=node[NODE_INDEX], )

    def manage_foreach_operation(self, node: py2neo.Node):
        a, a_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=0))
        if self.analyzer.get_ast_ith_child_node(node, i=2)[NODE_TYPE] == TYPE_NULL:

            v, v_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=1))
            a, a_type = self.gen_formula(
                left=a, right=[0, a], ltype='', rtype=['number', a_type], op='array_search', node_type=TYPE_CALL,
                node_id=node[NODE_INDEX]
            )
        else:

            k, k_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=1))
            v, v_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, i=2))
            a, a_type = self.gen_formula(
                left=a, right=[k, a], ltype='', rtype=[k_type, a_type], op='array_search', node_type=TYPE_CALL,
                node_id=node[NODE_INDEX]
            )
        return self.gen_formula(
            left=v, right=[a], ltype=v_type, rtype=[a_type], op=TYPE_ASSIGN, node_type=TYPE_ASSIGN,
            node_id=self.analyzer.get_ast_ith_child_node(node, i=1)[NODE_INDEX]
        )

    def manage_return_operation(self, node: py2neo.Node):
        return self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])

    def manage_condition_operation(self, node: py2neo.Node):

        _the_three = self.analyzer.find_ast_child_nodes(node)
        condition_node, true_path_node, false_path_node = _the_three[0], _the_three[1], _the_three[2]
        condition_expr, condition_type = self.manage_generic_node(condition_node)
        true_expr, true_type = self.manage_generic_node(true_path_node)
        false_expr, false_type = self.manage_generic_node(false_path_node)
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[condition_expr, true_expr, false_expr],
            op=TYPE_CONDITIONAL,
            node_type=TYPE_CONDITIONAL,
            node_id=node.identity,
            ltype="string",
            rtype=[condition_type, true_type, false_type]
        )

    def manage_null(self, node: py2neo.Node):
        return "null", ""

    def manage_ref(self, node: py2neo.Node):

        return self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])

    def manage_constant_string(self, node: py2neo.Node):
        if self.__global_normalize_level >=2:
            return "Constant", "string"
        if 'code' not in node.keys():
            return "\"\"", "string"
        else:
            code = node['code']
            return "\"" + addslashes(code) + "\"", "string"

    def manage_constant_integer(self, node: py2neo.Node):
        if self.__global_normalize_level >= 2:
            return "Constant", "number"
        if 'code' not in node.keys():
            return 0, "number"
        else:
            return int(node['code']), "number"

    def manage_constant_double(self, node: py2neo.Node):
        if self.__global_normalize_level >= 2:
            return "Constant", "number"
        if 'code' not in node.keys():
            return 0.0, "number"
        else:
            return float(node['code']), "number"

    def manage_type_array(self, node: py2neo.Node):
        args = self.analyzer.find_ast_child_nodes(node)
        resolved_array_elem = []
        resolved_array_elem_types = []
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            arg_expr, arg_type = self.manage_generic_node(arg)
            resolved_array_elem.append(arg_expr)
            resolved_array_elem_types.append(arg_type)
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_array_elem,
            op="array",
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="",
            rtype=resolved_array_elem_types
        )

    def manage_type_array_elem(self, node: py2neo.Node):
        assert node[NODE_TYPE] == TYPE_ARRAY_ELEM
        if self.analyzer.get_ast_ith_child_node(node, 1)['type'] == 'NULL':
            array_node = self.analyzer.ast_step.get_parent_node(node)
            ith_node = self.analyzer.find_ast_child_nodes(array_node).index(node)
            key_expr, key_type = ith_node, 'number'
            value_expr, value_type = self.manage_generic_node(self.analyzer.get_ast_child_node(node))
        else:
            key_expr, key_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, 1))
            value_expr, value_type = self.manage_generic_node(self.analyzer.get_ast_ith_child_node(node, 0))
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[key_expr, value_expr],
            op=TYPE_ARRAY_ELEM,
            node_type=TYPE_BINARY_OP,
            node_id=node.identity,
            ltype="",
            rtype=[key_type, value_type]
        )

    def manage_class_constant(self, node: py2neo.Node):
        code = self.analyzer.code_step.get_ast_class_const_code(node)
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[code],
            op=node[NODE_TYPE],
            node_type=node[NODE_TYPE],
            node_id=node.identity,
            ltype="string",
            rtype=['string']
        )

    def manage_magic_constant(self, node: py2neo.Node):
        return MAGIC_CONST_CONVERT_DICT[node['flags'][0]], "string"

    def manage_generic_constant(self, node: py2neo.Node):
        code = self.analyzer.code_step.get_ast_const_code(node)
        if code.lower() == "true":
            return True, "boolean"
        elif code.lower() == "false":
            return False, "boolean"
        else:
            if self.__global_normalize_level >= 2:
                code = "Constant"
            return self.gen_formula(
                left=join_var_node(node.identity),
                right=[code],
                op=node[NODE_TYPE],
                node_type=node[NODE_TYPE],
                node_id=node.identity,
                ltype="string",
                rtype=['string']
            )

    def manage_unary_operation(self, node: py2neo.Node):
        expr, expr_type = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        if node[NODE_TYPE] == 'AST_UNARY_OP' and set(node['flags']) & {FLAG_UNARY_SILENCE}:
            return expr, expr_type
        if node[NODE_TYPE] == 'AST_UNARY_OP' and set(node['flags']) & {"UNARY_BOOL_NOT"}:
            return self.gen_formula(join_var_node(node.identity), [expr], node['flags'][0], node[NODE_TYPE],
                                    node.identity,
                                    "boolean", ["boolean"])
        elif node[NODE_TYPE] == 'AST_UNARY_OP' and node['flags'][0] == "UNARY_MINUS":
            return self.gen_formula(join_var_node(node.identity), [expr], node['flags'][0], node[NODE_TYPE],
                                    node.identity,
                                    "number", ["number"])

        elif node[NODE_TYPE] == 'AST_POST_INC':
            self.gen_formula(join_var_node(node.identity), [expr], TYPE_ASSIGN, TYPE_ASSIGN, node.identity, "number",
                             ["number"])
            return self.gen_formula(expr, [expr, 1], 'BINARY_ADD', TYPE_BINARY_OP, node.identity, "number",
                                    ["number", "number"])

        elif node[NODE_TYPE] == 'AST_POST_DEC':
            self.gen_formula(join_var_node(node.identity), [expr], TYPE_ASSIGN, TYPE_ASSIGN, node.identity, "number",
                             ["number"])
            return self.gen_formula(expr, [expr, 1], 'BINARY_SUB', TYPE_BINARY_OP, node.identity, "number",
                                    ["number", "number"])

        elif node[NODE_TYPE] == 'AST_PRE_INC':
            return self.gen_formula(expr, [expr, 1], 'BINARY_ADD', TYPE_BINARY_OP, node.identity, "number",
                                    ["number", "number"])

        elif node[NODE_TYPE] == 'AST_PRE_DEC':
            return self.gen_formula(expr, [expr, 1], 'BINARY_SUB', TYPE_BINARY_OP, node.identity, "number",
                                    ["number", "number"])

        elif node[NODE_TYPE] == TYPE_CAST:
            if node['flags'][0] in {FLAG_TYPE_LONG}:
                return self.gen_formula(expr, [expr], 'intval', TYPE_CALL, node.identity, "number", ["number"])
            elif node['flags'][0] in {FLAG_TYPE_DOUBLE}:
                return self.gen_formula(expr, [expr], 'floatval', TYPE_CALL, node.identity, "number", ["number"])
            elif node['flags'][0] in {FLAG_TYPE_STRING}:
                return self.gen_formula(expr, [expr], 'strval', TYPE_CALL, node.identity, "string", ["string"])
            elif node['flags'][0] in {FLAG_TYPE_BOOL}:
                return self.gen_formula(expr, [expr], 'boolval', TYPE_CALL, node.identity, "boolean", ["boolean"])
            elif node['flags'][0] in {FLAG_TYPE_OBJECT}:
                return self.gen_formula(expr, [expr], '(object)', TYPE_CALL, node.identity, "", [""])
            elif node['flags'][0] in {FLAG_TYPE_ARRAY}:
                return self.gen_formula(expr, [expr], '(array)', TYPE_CALL, node.identity, "", [""])
            else:
                logger.warning(f"not support cast type {node['flags']} , use strval instead")
                return self.gen_formula(expr, [expr], 'strval', TYPE_CALL, node.identity, "string", ["string"])

    def manage_assignment_operation(self, node: py2neo.Node):
        assert not set(node[NODE_TYPE]) & {TYPE_ASSIGN, TYPE_ASSIGN_REF, TYPE_ASSIGN_OP}
        l_expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        r_expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[1])
        if node[NODE_TYPE] == TYPE_ASSIGN_REF:
            return self.gen_formula(
                left=l_expr[0], right=[r_expr[0]], op=TYPE_ASSIGN, node_type=TYPE_ASSIGN, node_id=node.identity,
                ltype=solve_type_conflict(l_expr[1], r_expr[1]), rtype=[solve_type_conflict(l_expr[1], r_expr[1])],
            )

        if node[NODE_TYPE] in {TYPE_ASSIGN, TYPE_STATIC}:
            return self.gen_formula(
                left=l_expr[0], right=[r_expr[0]], op=TYPE_ASSIGN, node_type=TYPE_ASSIGN, node_id=node.identity,
                ltype=solve_type_conflict(l_expr[1], r_expr[1]), rtype=[solve_type_conflict(l_expr[1], r_expr[1])],
            )
        elif node[NODE_TYPE] == TYPE_ASSIGN_OP:
            if node['flags'][0] in {FLAG_BINARY_CONCAT}:
                tmp_expr = self.gen_formula(
                    left=join_var_node(node.identity),
                    right=[l_expr[0], r_expr[0]],
                    op=node['flags'][0],
                    node_type=TYPE_BINARY_OP,
                    node_id=node.identity,
                    ltype='string',
                    rtype=['string', 'string']
                )
                return self.gen_formula(
                    left=l_expr[0], right=[tmp_expr[0]], op=node[NODE_TYPE], node_type=TYPE_ASSIGN,
                    node_id=node.identity,
                    ltype=solve_type_conflict(l_expr[1], tmp_expr[1]),
                    rtype=[solve_type_conflict(l_expr[1], tmp_expr[1])],
                )
            elif node['flags'][0] in {FLAG_BINARY_BITWISE_AND, FLAG_BINARY_BITWISE_XOR, FLAG_BINARY_BITWISE_OR}:
                tmp_expr = self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                            TYPE_BINARY_OP, node.identity, "boolean", ["boolean", "boolean"])
                return self.gen_formula(l_expr[0], [tmp_expr[0]], node['flags'][0],
                                        TYPE_ASSIGN, node.identity, "boolean", [tmp_expr[1]])
            elif node['flags'][0] in {FLAG_BINARY_ADD, FLAG_BINARY_SUB, FLAG_BINARY_MUL, FLAG_BINARY_DIV,
                                      FLAG_BINARY_MOD, FLAG_BINARY_POW, FLAG_BINARY_SHIFT_LEFT,
                                      FLAG_BINARY_SHIFT_RIGHT}:
                tmp_expr = self.gen_formula(join_var_node(node.identity), [l_expr[0], r_expr[0]], node['flags'][0],
                                            TYPE_BINARY_OP, node.identity, "number", ["number", "number"])
                return self.gen_formula(l_expr[0], [tmp_expr[0]], node['flags'][0],
                                        TYPE_ASSIGN, node.identity, "number", [tmp_expr[1]])
            else:
                raise Exception(node[NODE_TYPE])
        else:
            raise Exception(node[NODE_TYPE])

    def manage_echo_operation(self, node: py2neo.Node):
        op = 'Sink' if self.__global_normalize_level >= 2 else 'echo'
        expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr[0]],
            op=op,
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="string",
            rtype=["string"]
        )

    def manage_unset_operation(self, node: py2neo.Node):
        expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr[0]],
            op='unset',
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="boolean",
            rtype=[expr[1]]
        )

    def manage_isset_operation(self, node: py2neo.Node):
        expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr[0]],
            op='isset',
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="boolean",
            rtype=[expr[1]]
        )

    def manage_encapsulated_list(self, node: py2neo.Node):
        pre_tmp = None
        __nodes = self.analyzer.find_ast_child_nodes(node)
        for __node in __nodes:
            expr = self.manage_generic_node(__node)
            if pre_tmp is None:
                pre_tmp = expr[0]
            else:
                pre_tmp, _ = self.gen_formula(
                    left=join_var_node(node.identity, ADD_ENC_FLAG=True),
                    right=[pre_tmp, expr[0]],
                    op='BINARY_CONCAT',
                    node_type="AST_BINARY_OP",
                    node_id=node.identity,
                    ltype="string",
                    rtype=["string", "string"]
                )
        assert pre_tmp is not None
        return pre_tmp, "string"

    def manage_static_function_call(self, node: py2neo.Node):
        args = self.analyzer.ast_step.find_function_arg_node_list(node)
        resolved_args = []
        resolved_args_types = []
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            res_arg = self.manage_generic_node(arg)
            resolved_args.append(res_arg[0])
            resolved_args_types.append(res_arg[1])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_args,
            op=self.analyzer.code_step.get_ast_static_call_code(node),
            node_type=TYPE_STATIC_CALL,
            node_id=node.identity,
            ltype="string",
            rtype=resolved_args_types
        )

    def manage_dynamic_function_call(self, node: py2neo.Node):
        args = self.analyzer.ast_step.find_function_arg_node_list(node)
        resolved_args = []
        resolved_args_types = []
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            res_arg = self.manage_generic_node(arg)
            resolved_args.append(res_arg[0])
            resolved_args_types.append(res_arg[1])
        var_node = self.analyzer.get_ast_child_node(node)
        var_expr, var_type = self.manage_generic_node(var_node)
        resolved_args = [var_expr] + resolved_args
        resolved_args_types = [var_type] + resolved_args_types
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_args,
            op=self.analyzer.code_step.get_ast_method_call_code(node),
            node_type=TYPE_METHOD_CALL,
            node_id=node.identity,
            ltype="string",
            rtype=resolved_args_types
        )

    def manage_include_operation(self, node: py2neo.Node):
        op = 'Sink' if self.__global_normalize_level >= 2 else 'include'
        expr = self.manage_generic_node(self.analyzer.find_ast_child_nodes(node)[0])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr[0]],
            op=op,
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="boolean",
            rtype=["string"]
        )

    def manage_eval_operation(self, node: py2neo.Node):
        op = 'Sink' if self.__global_normalize_level >= 2 else 'eval'
        expr = self.manage_generic_node(self.analyzer.get_ast_child_node(node))
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=[expr[0]],
            op=op,
            node_type=TYPE_CALL,
            node_id=node.identity,
            ltype="",
            rtype=["string"]
        )

    def manage_type_prop(self, node: py2neo.Node):
        resolved_args = []
        resolved_args_types = []
        args = self.analyzer.find_ast_child_nodes(node)
        for arg in args:
            assert isinstance(arg, py2neo.Node)
            res_arg = self.manage_generic_node(arg)
            resolved_args.append(res_arg[0])
            resolved_args_types.append(res_arg[1])
        return self.gen_formula(
            left=join_var_node(node.identity),
            right=resolved_args,
            op=TYPE_PROP,
            node_type=TYPE_PROP,
            node_id=node.identity,
            ltype="string",
            rtype=resolved_args_types
        )
