import json
import logging

from core.neo4j_engine.const import *

logger = logging.getLogger(__name__)

LOG_PATH = './tmp'


class CodeToOpConverter(object):
    def __init__(self, ast_type, python_code, php_code, z3_code):
        self.ast_type = ast_type
        self.python_code = python_code
        self.php_code = php_code
        self.z3_code = z3_code


def convert_op_to_code(op, search_type: str = "php"):
    code_to_op_converter_dict = {
            TYPE_REF: CodeToOpConverter(TYPE_REF, "", "&", "&"),
            TYPE_NEW: CodeToOpConverter(TYPE_NEW, "", "new", None),
            TYPE_ARRAY_ELEM: CodeToOpConverter("AST_ARRAY_ELEM", ":", "=>", None),
            "BINARY_CONCAT": CodeToOpConverter("BINARY_CONCAT", "+", ".", "in"),
            "UNARY_BOOL_NOT": CodeToOpConverter("UNARY_BOOL_NOT", "not", "!", "!"),
            "UNARY_MINUS": CodeToOpConverter("UNARY_MINUS", "-", "-", "-"),
            "BINARY_IS_SMALLER": CodeToOpConverter("BINARY_IS_SMALLER", "<", "<", "<"),
            "BINARY_IS_SMALLER_OR_EQUAL": CodeToOpConverter("BINARY_IS_SMALLER_OR_EQUAL", "<=", "<=", "<="),
            "BINARY_IS_GREATER": CodeToOpConverter("BINARY_IS_GREATER", ">", ">", ">"),
            "BINARY_IS_GREATER_OR_EQUAL": CodeToOpConverter("BINARY_IS_GREATER_OR_EQUAL", ">=", ">=", ">="),
            "BINARY_BOOL_AND": CodeToOpConverter("BINARY_BOOL_AND", "and", "&&", "and"),
            "BINARY_BOOL_OR": CodeToOpConverter("BINARY_BOOL_OR", "or", "||", "or"),
            "BINARY_BOOL_XOR": CodeToOpConverter("BINARY_BOOL_XOR", "xor", "xor", "xor"),
            "BINARY_ADD": CodeToOpConverter("BINARY_ADD", "+", "+", "+"),
            "BINARY_SUB": CodeToOpConverter("BINARY_SUB", "-", "-", "-"),
            "BINARY_MUL": CodeToOpConverter("BINARY_MUL", "*", "*", "*"),
            "BINARY_DIV": CodeToOpConverter("BINARY_DIV", "/", "/", "div"),
            "BINARY_MOD": CodeToOpConverter("BINARY_MOD", "%", "mod", "mod"),
            "BINARY_POW": CodeToOpConverter("BINARY_POW", "**", "pow", "^"),
            "BINARY_IS_EQUAL": CodeToOpConverter("BINARY_IS_EQUAL", "==", "==", "="),
            "BINARY_IS_NOT_EQUAL": CodeToOpConverter("BINARY_IS_NOT_EQUAL", "!=", "!=", "!="),
            "BINARY_IS_IDENTICAL": CodeToOpConverter("BINARY_IS_IDENTICAL", "==", "===", "="),
            "BINARY_IS_NOT_IDENTICAL": CodeToOpConverter("BINARY_IS_NOT_IDENTICAL", "!=", "!==", "!="),
            FLAG_BINARY_BITWISE_OR: CodeToOpConverter(FLAG_BINARY_BITWISE_OR, "|", "|", "|"),
            FLAG_BINARY_BITWISE_XOR: CodeToOpConverter(FLAG_BINARY_BITWISE_XOR, "^", "^", "^"),
            FLAG_BINARY_BITWISE_AND: CodeToOpConverter(FLAG_BINARY_BITWISE_AND, "&", "&", "&"),
            FLAG_BINARY_SHIFT_LEFT: CodeToOpConverter(FLAG_BINARY_SHIFT_LEFT, "<<", "<<", "<<"),
            FLAG_BINARY_SHIFT_RIGHT: CodeToOpConverter(FLAG_BINARY_SHIFT_RIGHT, ">>", ">>", ">>"),
            TYPE_INSTANCEOF: CodeToOpConverter(TYPE_INSTANCEOF, "isinstance", "instance of", "")
    }
    assert {search_type} & {"php", "python", "z3"}
    if search_type == "php":
        return code_to_op_converter_dict[op].php_code
    elif search_type == "python":
        return code_to_op_converter_dict[op].python_code
    elif search_type == "z3":
        return code_to_op_converter_dict[op].z3_code
    else:
        logger.warning(f"not support type {op}")
        return None


def convert_op_to_real_code(op):
    return convert_op_to_code(op, search_type="php")


class Formula(object):
    def __init__(self, left, right, op, node_type, node_id):
        self.left = left
        self.right = right
        self.op = op
        self.type = node_type
        self.node_id = node_id


class Type(object):
    def __init__(self, left, right):
        self.right = right
        self.left = left


class ThreeAddressCode(object):
    def __init__(self, left: str, right: list, op: str, node_type: str, node_id: int, ltype: str, rtype: list) -> None:
        self.__index = 0
        self.formula = Formula(
                left, right, op, node_type, node_id
        )
        self.type = Type(
                ltype, rtype
        )

    def to_src_code(self):
        if self.formula.type in [TYPE_CALL]:
            return f"{self.formula.left} ={self.formula.op}(" + "".join(i + "," for i in self.formula.right) + ")"
        if self.formula.type in [TYPE_BINARY_OP]:
            return f"{self.formula.left}  = {self.formula.right[0]} {self.formula.op} {self.formula.right[1]} "

    def set_tac_index(self, _index):
        self.__index = _index

    def to_markdown(self):
        return f"|\t{self.formula.left}\t|" \
               f"\t{self.formula.right}\t|" \
               f"\t{self.formula.op}\t|" \
               f"\t{self.formula.type}\t|" \
               f"\t{self.formula.node_id}\t|" \
               f"\t{self.type.left}\t|" \
               f"\t{self.type.right}\t|".replace("$", "\$")

    def to_csv(self):
        return f"{self.formula.left},{self.formula.right},{self.formula.op},{self.formula.type},{self.formula.node_id},{self.type.left},{self.type.right}"

    def to_json(self):
        return json.dumps(self.__dict__, default=lambda o: o.__dict__)

    def __str__(self):
        return self.to_csv()


class ThreeAddressCodePath(object):
    def __init__(self):
        self.__mem = []
        self.__var_index = -1
        self.HEADER = ['left', 'right', 'op', 'type', 'node_id', 'type_left', 'type_right']

    def __len__(self):
        return self.__mem.__len__()

    def append(self, __object: ThreeAddressCode) -> None:
        self.__var_index += 1
        __object.set_tac_index(self.__var_index)
        self.__mem.append(__object)

    def get_push_info(self, index):
        return self.__mem[index].__str__()

    def to_raw_code(self):
        expr_cache = {}
        if self.__mem.__len__() == 0:
            return "", ""
        final_var = self.__mem[-1].formula.left

        def __get_exprt_cache(k):
            if isinstance(k, bool) or isinstance(k, int) or isinstance(k, float):
                return str(k)
            for _k in expr_cache.keys():
                k = k.replace(_k, expr_cache[_k])
            return k

        for _mem in self.__mem:
            assert isinstance(_mem, ThreeAddressCode)
            if _mem.formula.type == TYPE_BINARY_OP:
                op = convert_op_to_real_code(_mem.formula.op)
                assert _mem.formula.right.__len__() == 2 and _mem.type.right.__len__() == 2
                src1 = __get_exprt_cache(_mem.formula.right[0])
                src2 = __get_exprt_cache(_mem.formula.right[1])
                if _mem.formula.op in {TYPE_ARRAY_ELEM, TYPE_CAST, FLAG_BINARY_CONCAT, TYPE_INSTANCEOF}:
                    expr_cache[_mem.formula.left] = f"{src1} {op} {src2}"
                else:
                    expr_cache[_mem.formula.left] = f"({src1} {op} {src2})"
            elif _mem.formula.type == TYPE_UNARY_OP:
                assert _mem.formula.right.__len__() == 1 and _mem.type.right.__len__() == 1
                op = convert_op_to_real_code(_mem.formula.op)
                src = __get_exprt_cache(_mem.formula.right[0])
                if op in {"&"}:
                    expr_cache[_mem.formula.left] = f"{op}{src}"
                else:
                    expr_cache[_mem.formula.left] = f"{op} {src}"
            elif _mem.formula.type == TYPE_CALL:
                __buffer = "".join(__get_exprt_cache(i) + "," for i in _mem.formula.right)[:-1]
                expr_cache[_mem.formula.left] = f"{_mem.formula.op}({__buffer})"
            elif _mem.formula.type in {TYPE_ASSIGN, TYPE_CONST, TYPE_CLASS_CONST, }:
                src = __get_exprt_cache(_mem.formula.right[0])
                expr_cache[_mem.formula.left] = src
            elif _mem.formula.type == TYPE_METHOD_CALL:
                _var = __get_exprt_cache(_mem.formula.right[0])
                _real_right = _mem.formula.right[1:]
                __buffer = "".join(__get_exprt_cache(i) + "," for i in _real_right)[:-1]
                expr_cache[_mem.formula.left] = f"{_var}->{_mem.formula.op}({__buffer})"
            elif _mem.formula.type == TYPE_PROP:
                _var = __get_exprt_cache(_mem.formula.right[0])
                _real_right = _mem.formula.right[1:]
                __buffer = "".join(__get_exprt_cache(i) + "," for i in _real_right)[:-1]
                __buffer = __buffer.replace("\"", "").replace("\'", "")
                expr_cache[_mem.formula.left] = f"{_var}->{__buffer}"
            elif _mem.formula.type == TYPE_STATIC_CALL:
                __buffer = "".join(__get_exprt_cache(i) + "," for i in _mem.formula.right)[:-1]
                expr_cache[_mem.formula.left] = f"{_mem.formula.op}({__buffer})"
            elif _mem.formula.type == TYPE_CONDITIONAL:
                _c, _t, _f = __get_exprt_cache(_mem.formula.right[0]), __get_exprt_cache(
                        _mem.formula.right[1]), __get_exprt_cache(_mem.formula.right[2])
                expr_cache[_mem.formula.left] = f"{_c} ? {_t} : {_f}"
            elif _mem.formula.type in {TYPE_ASSIGN}:
                __tmp = __get_exprt_cache(_mem.formula.right[0])
                expr_cache[_mem.formula.left] = f"{_mem.formula.left}={__tmp}"
        return final_var, expr_cache[final_var]
