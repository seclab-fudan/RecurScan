class ModifiedLine(object):
    def __init__(self, lineno, root_node, operation):
        self.lineno = lineno
        self.root_node = root_node
        self.operation = operation

    def __eq__(self, other):
        return self.lineno == other.lineno and self.root_node == other.root_node and (
                self.operation == other.operation)

    def __str__(self):
        return "lineno:%s root_node:%s operation:%s " % (
            self.lineno, self.root_node, self.operation)
