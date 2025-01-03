import networkx

from util import Operation, Identifier, AddrSpace, InstructionReference


class DecompState:
    # Represents the state of the data flow graph at a specific point in the
    # decompilation process
    _state: networkx.DiGraph
    _pcode: str
    _rule_name: str

    def __init__(self, rule_name: bytes, pcode: bytes):
        self._rule_name = rule_name.decode('utf-8')
        self._pcode = pcode.decode('utf-8').removeprefix('0\n')
        self._init_state(self._pcode)

    def _init_state(self, raw_pcode: str):
        # Create a data flow graph out of the given operations

        edges_to_create: list[
            tuple[tuple[int, int] | InstructionReference | Identifier | AddrSpace, tuple[int, int] | InstructionReference | Identifier]
        ] = []

        operations = [
            Operation.from_raw(line.replace("\t", " ").encode("utf-8"))
            for line in raw_pcode.split("\n")
            if line and not line.startswith("Basic Block")
        ]

        self._state = networkx.DiGraph()

        for op in operations:
            # Add node
            assert op._addr not in self._state, f"{op._addr} already in graph"
            self._state.add_node(op._addr, node_item=op)

            # Add output edge (and output varnode if it doesn't exist already)
            if op._out is not None:
                out_node = op._out

                if out_node not in self._state:
                    self._state.add_node(out_node, node_item=out_node)

                edges_to_create.append((op._addr, out_node))

            # Add input edges (and varnodes if necessary)
            for inp in op._in:
                if inp is None:
                    print(f"Warning: Operation {op} has None as input")
                    continue

                if inp not in self._state:
                    self._state.add_node(inp, node_item=inp)

                if isinstance(inp, InstructionReference):
                    # Special case for instruction references - Add extra edge
                    # to reference target.
                    target = inp._target._seq_num
                    if target is None:
                        print(f"Warning: Instruction reference to None: {inp}")
                    else:
                        edges_to_create.append((target, inp, {'dotted': True}))

                edges_to_create.append((inp, op._addr))

        self._state.add_edges_from(edges_to_create)

    def get_graph(self) -> networkx.DiGraph:
        return self._state

    def get_pcode(self) -> str:
        """
        Returns a string containing the P-CODE at this point in the
        decompilation process.
        """
        return self._pcode


class Decomp:
    _states: list[DecompState]

    def __init__(self, pcodes: list[tuple[bytes, bytes]]):
        self._states = [
            DecompState(rule_name, pcode) for rule_name, pcode in pcodes
        ]

    def get_rule_names(self) -> list[str]:
        return [s._rule_name for s in self._states]

    def get_state(self, idx: int) -> DecompState:
        return self._states[idx]
