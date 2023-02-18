import networkx

import random
import typing
import copy

from util import Operation, Identifier, AddrSpace, InstructionReference

class DecompStep:
    _lines: bytes
    _id: int
    _rule_name: str
    _changes: list[tuple[Operation, Operation]]

    def __init__(self, debug_output: bytes):
        # DEBUG {id}: {rule_name}
        # {old_line}
        #    {new_line}
        # {for old_line, new_line in changed_lines}
        self._lines = debug_output
        lines = debug_output.split(b"\n")

        top_line_parts = lines[0].split(b" ", 2)
        assert top_line_parts[0] == b"DEBUG", top_line_parts
        self._id = int(top_line_parts[1].rstrip(b":"))
        self._rule_name = top_line_parts[2].decode('utf-8')

        self._changes = []
        for change_line_num in range((len(lines) - 1) // 2):
            old_line = Operation.from_raw(lines[1 + change_line_num * 2])
            new_line = Operation.from_raw(lines[2 + change_line_num * 2])
            self._changes.append((old_line, new_line))

    def __str__(self) -> str:
        return f"DecompStep {self.get_short_desc()}\nChanges:\n  " + "\n  ".join(["\n    ->\n  ".join(map(str, c)) for c in self._changes]) + f"\n{self._lines.decode('utf-8')}"

    def get_short_desc(self) -> str:
        return f"{self._id} (rule: {self._rule_name!r})"

class DecompState:
    # Represents the state of the data flow graph at a specific point in the
    # decompilation process
    _state: networkx.DiGraph

    def __init__(self, prev_state: typing.Optional['DecompState'] = None):
        if prev_state is not None:
            self._state = prev_state.get_graph().copy()
        else:
            self._state = networkx.DiGraph()

    def set_state(self, operations: list[Operation]):
        # Create a data flow graph out of the given operations

        edges_to_create: list[tuple[str | Identifier | AddrSpace, str | Identifier | Operation]] = []

        for op in operations:
            # Add node
            self._state.add_node(op._addr, op=op._op, is_varnode=False, name=op._op)

            # Add output edge (and output varnode if it doesn't exist already)
            if op._out is not None:
                out_node = op._out
                assert isinstance(out_node, Identifier), (type(out_node), out_node)

                if out_node not in self._state:
                    self._state.add_node(out_node, op=None, is_varnode=True, name=str(out_node))

                edges_to_create.append((op._addr, out_node))

            # Add input edges (and varnodes if necessary)
            for inp in op._in:
                if inp is None: continue  # BUG?
                assert isinstance(inp, (Identifier, AddrSpace, InstructionReference)), (type(inp), inp)

                if isinstance(inp, InstructionReference):
                    # Special case for instruction references - directly link
                    # the operation being referenced to the current operation.
                    # TODO: Maybe make this a dotted line?
                    edges_to_create.append((inp._target_addr, op))

                else:
                    if inp not in self._state:
                        self._state.add_node(inp, op=None, is_varnode=True, name=str(inp))

                    edges_to_create.append((inp, op._addr))

        self._state.add_edges_from(edges_to_create)

    def apply(self, step: DecompStep):

        for old_line, new_line in step._changes:

            if not old_line._is_empty:
                # Remove node (also removes edges)
                nodes_to_remove = []

                # Remove nodes that point into only this node
                for in_varnode in self._state.predecessors(old_line._addr):
                    assert self._state.has_node(in_varnode), (in_varnode, "not a node")

                    if self._state.in_degree(in_varnode) == 0 and self._state.out_degree(in_varnode) == 1:
                        nodes_to_remove.append(in_varnode)

                # Remove output nodes that don't flow any further
                for out_varnode in self._state.successors(old_line._addr):
                    assert self._state.has_node(out_varnode), (out_varnode, "not a node")

                    if self._state.out_degree(out_varnode) == 0 and self._state.in_degree(out_varnode) == 1:
                        nodes_to_remove.append(out_varnode)

                # print("Removing nodes " + str(nodes_to_remove))
                self._state.remove_node(old_line._addr)
                self._state.remove_nodes_from(nodes_to_remove)

            if not new_line._is_empty:
                # Add node
                self._state.add_node(new_line._addr, op=new_line._op, is_varnode=False, name=new_line._op)

                # Add new edges
                if new_line._out is not None:
                    out_node = new_line._out
                    assert isinstance(out_node, Identifier), (type(out_node), out_node)

                    if out_node not in self._state:
                        self._state.add_node(out_node, op=None, is_varnode=True, name=str(out_node))

                    self._state.add_edge(new_line._addr, out_node)

                for inp in new_line._in:
                    if inp is None: continue  # BUG?
                    assert isinstance(inp, (Identifier, AddrSpace, InstructionReference)), (type(inp), inp)

                    if inp not in self._state:
                        self._state.add_node(inp, op=None, is_varnode=True, name=str(inp))

                    self._state.add_edge(inp, new_line._addr)

    def get_graph(self) -> networkx.DiGraph:
        return self._state

class Decomp:
    _steps: list[DecompStep]
    _states: list[DecompState]

    def __init__(self, initial_pcode: bytes):
        self._steps = []
        initial_state = DecompState()
        initial_state.set_state([
            Operation.from_raw(line.replace(b"\t", b" "))
            for line in initial_pcode.split(b"\n")
            if b":" in line
        ])
        self._states = [initial_state]

    def add_step(self, step: DecompStep):
        self._steps.append(step)

        if not self._states:
            new_state = DecompState()
        else:
            new_state = DecompState(self._states[-1])

        new_state.apply(step)
        self._states.append(new_state)

    def get_step(self, index: int) -> DecompStep:
        return self._steps[index]

    def get_num_steps(self) -> int:
        return len(self._steps)

    def get_state(self, idx: int) -> DecompState:
        return self._states[idx]
