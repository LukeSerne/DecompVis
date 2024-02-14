import networkx

import subprocess
from dataclasses import dataclass
import typing
import traceback
import itertools

def get_decompile_data(decomp_path: str, ghidra_path: str, xml_path: str, func_name: str, extra_paths: list[str]) -> tuple[bytes, list[bytes]]:
    """
    Executes the decompiler on the given xml file and returns the P-CODE diffs
    and initial P-CODE.
    """

    # Construct the full command, including extra paths for language
    # definitions. The resulting command will be [decomp_path] if no extra_paths
    # are given, and [decomp_path, '-s', path_1, '-s', path_2] if 2 extra_paths
    # are given.
    command_args = zip(['-s'] * len(extra_paths), extra_paths)
    command = [decomp_path] + list(itertools.chain.from_iterable(command_args))

    # TODO: This converts str to bytes only for later functions (eg. Operation::from_raw)
    # to convert the bytes back to str. Consider just returning str from this
    # function.

    input_commands = (
        f"restore {xml_path}\n"
        f"load function {func_name}\n"
        "trace address\n"
        "print raw\n"
        "decompile\n"
        "quit\n"
    )

    output = subprocess.run(
        command, input=input_commands, env={"SLEIGHHOME": ghidra_path},
        capture_output=True, check=True, text=True
    ).stdout

    # -1 is used as index to select the first element of the split if the
    # function is not namespaced
    bare_func_name = func_name.rsplit("::", 1)[-1]

    lines = output.split("\n")
    if not lines[1].startswith(f"{xml_path} successfully loaded: "):
        raise ValueError(f"Unexpected response to 'restore {xml_path}': {lines[1]!r}")
    if not lines[3].startswith(f"Function {bare_func_name}: "):
        raise ValueError(f"Unexpected response to 'load function {func_name}': {lines[3]!r}")
    if lines[5] != "OK (1 ranges)":
        raise ValueError(f"Unexpected response to 'trace address': {lines[5]!r}")

    # Calculate begin and end of the decompilation output
    decomp_cmd_idx = lines.index("[decomp]> decompile")
    decomp_end_idx = lines.index("Decompilation complete", decomp_cmd_idx)

    # The first 7 lines are other output (our previous commands and responses),
    # so skip those.
    initial_pcode = "\n".join(lines[7:decomp_cmd_idx]).encode("utf-8")

    # The line after the decomp_cmd_idx is "Decompiling {func_name}", which we
    # don't want in our output
    decomp_log = "\n".join(lines[decomp_cmd_idx + 2:decomp_end_idx]).encode("utf-8").split(b"\n\n")

    return initial_pcode, decomp_log

def make_xpath_string(string: str) -> str:
    """
    Takes a Python string and converts it to a string representing an XPath
    expression that represents the same string value. Note that this only
    targets the limited subset of XPath supported by Python's xml.etree.ElementTree,
    as described here: https://docs.python.org/3/library/xml.etree.elementtree.html#supported-xpath-syntax

    Raises a ValueError if the input string cannot be represented.
    """
    if "'" in string or '"' in string:
        raise ValueError(f"XPath strings (as supported by xml.etree.ElementTree) cannot contain any quotes, got {string!r}")

    # The string does not contain any quotes, so we can safely wrap it using
    # single quotes.
    return "'" + string + "'"

def find_matching_open_paren_to_final_close_paren(string: str) -> int:
    """
    Returns the index of the matching '(' for the ')' that ends the input string.
    """
    nest_level: int = 0
    for i, c in enumerate(reversed(string)):
        if c == ")":
            nest_level += 1
        elif c == "(":
            nest_level -= 1

        if nest_level == 0:
            break

    else:
        raise ValueError(f"Input string was not balanced! {string!r}")

    return len(string) - 1 - i

def grid_cell_position(G: networkx.DiGraph) -> tuple[dict["Node", tuple[float, float]], list[float]]:
    """
    Assuming the graph is directed and acyclic, this will return the positions
    to plot the graph in a hierarchical layout. The edges will point downwards
    as much as possible.

    G: the graph (must not have a cycle)
    """
    # TODO: Sometimes, edges are horizontal or point upwards. This happens when
    # a node is connected to multiple sinks and the distance of the node to the
    # first sink is smaller than the distance of the node to a later sink.
    # TODO: The order of the parents of a node doesn't correspond to the order
    # of the inputs to an operation.
    # TODO: Sometimes the super-tree of one parent uses multiple columns,
    # displacing the super-tree of another parent. Since the other parent's
    # super-tree is laid out in the columns to the right of the first parent,
    # there can be a needlessly big gap between the super-trees of the parents.
    # This is especially pronounced when the super-tree of the first parent is
    # much larger than the super-tree of the second parent.

    # Go through all parents, assign them their own columns and recursively
    # process them.
    def f(data: dict, sink: "Node", column_id: float, column_width: float, row_id: int) -> dict:
        nonlocal G

        # Set data for sink
        data[sink] = (column_id, row_id)
        parents = tuple(G.predecessors(sink))

        if not parents:
            # No parents -> end
            return data

        num_parents = len(parents)
        parent_width = column_width / num_parents

        # Pick new column ids
        column_idx = 0
        for parent in parents:
            if parent in data:  # The parent has already been placed in the grid
                continue

            parent_col_id = column_id + parent_width * column_idx
            assert column_id <= parent_col_id < column_id + parent_width * (column_idx + 1), (column_idx, column_id, parent_width, parent_col_id)

            data = f(data, parent, parent_col_id, parent_width, row_id - 1)
            column_idx += 1

        return data

    # Find the sink
    sinks = [node for node, out_deg in G.out_degree() if out_deg == 0]
    pos_data = {}

    for i, sink in enumerate(sinks):
        pos_data = f(pos_data, sink, i * 1000, 1000, 0)

    columns = sorted(set(pos_data[x][0] for x in pos_data))
    return pos_data, columns

def layout_algorithm(graph: networkx.DiGraph) -> dict["Node", tuple[float, float]]:
    """
    Takes a directed graph and returns a mapping of nodes to their position in
    the final layout.
    """
    # In general, the graph consists of several disconnected directed, acyclic
    # graphs. To find an good layout, we will separate these components and find
    # a layout for each component individually. Finally, we combine these
    # layouts into a single layout.
    layout = {}
    num_columns = 0

    column_width = 100  # width of a single column
    row_height = 100  # height of a cell

    for group_nodes in networkx.weakly_connected_components(graph):
        group = graph.subgraph(group_nodes)
        group_layout, group_columns = grid_cell_position(group)

        # Now turn the column and row ids into actual (x, y) positions
        for node, (col_id, row_id) in group_layout.items():
            layout[node] = ((num_columns + group_columns.index(col_id)) * column_width, row_id * row_height)

        num_columns += len(group_columns)

    return layout

@dataclass(frozen=True)
class AddrSpace:
    _name: str = ""

    def __str__(self) -> str:
        return f"AddrSpace({self._name})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, AddrSpace): return NotImplemented

        return self._name == other._name

    def __hash__(self) -> int:
        return (self._name,).__hash__()

    @staticmethod
    def from_raw(name: str) -> "AddrSpace":
        return AddrSpace(name)

    def get_node_name(self) -> str:
        return f"{self._name}"

    def get_color_name(self) -> str:
        return "brown"

    def get_tooltip_text(self) -> typing.Optional[str]:
        return None

@dataclass(frozen=True)
class Identifier:
    # Actually a Varnode
    _is_free: bool = False
    _is_input: bool = False
    _is_written: bool = False
    _size: typing.Optional[int] = None
    _seq_num: typing.Optional[tuple[int, int]] = None
    _space_shortcut: str = ""
    _name: str = ""

    @staticmethod
    def from_raw(name: str, no_size: bool = False) -> "Identifier":
        # base:
        # <reg>
        # <reg>\+\d+
        # <space_shortcut><storage_location>

        # suffices:
        # :<size>   <- if the size is unexpected
        # (i)       <- if input
        # (seq_num) <- if isWritten
        # (free)    <- if insert or constant
        is_input, is_free, is_written, seq_num = False, False, False, None

        # First remove suffices:
        while name.endswith(")"):
            start_idx = find_matching_open_paren_to_final_close_paren(name)
            part = name[start_idx:]

            if part == "(i)":
                is_input = True
            elif part == "(free)":
                is_free = True
            elif part.startswith("(0x"):
                # part might be "(0x800fb41c:61)"
                is_written = True
                seq_num = tuple(map(lambda s: int(s, 16), part[1:-1].split(":")))
            else:
                # part might be:
                # - "(#0x6)" or
                # - "(u0x1000000e:1(0x02a42310:99c))" or
                # - "(r3(i))"
                # Optional function arg?? Ignore these for now.
                # TODO: Figure out when these args are printed and decide how to
                # parse them
                try:
                    Identifier.from_raw(part[1:-1])
                except:
                    print(f"Warning: Unexpected parenthesised group at the end of varnode: {name!r}")
                    traceback.format_exc()

            name = name[:start_idx]

        # Then check for size modifier - make sure to not misidentify the size
        # if there is a colon in the name.
        size = None
        if not no_size:
            if ":" in name:
                name, size_ = name.rsplit(":", 1)
                try:
                    size = int(size_)
                except ValueError:
                    # This was probably a function name / storage location with a
                    # colon in it.
                    name += ":" + size_

            if size is None:
                # TODO: Somehow calculate the expected size
                # print(f"Implicit size for {name!r}")
                size = 4

        # Now parse the base name:
        is_addr = lambda n: n.startswith("invalid_addr") or n.startswith("0x")
        space_shortcut = name[0]

        def parse_addr_space(data: str) -> typing.Optional[str]:
            """
            Parses an address space description, as produced by 'AddrSpace::printRaw',
            and returns a normalised string version. If parsing fails, this
            function returns None.
            """
            if not data.startswith("0x"): return
            if "+" in data:
                addr_part = data[:data.index("+")]
                plus_part = int(data[data.index("+") + 1:], 10)
                if plus_part <= 0: return
            else:
                addr_part = data
                plus_part = 0

            if len(addr_part) not in (4, 6, 8, 10, 14): return
            addr_part = int(addr_part[2:], 16)

            return f"{addr_part:#x}+{plus_part}"

        # Ref: 'AddrSpaceManager::assignShortcut' in translate.cc
        is_parsed = False
        if space_shortcut == "#" and name.startswith("#0x"):  # IPTR_CONSTANT
            # name = "#0x" value
            # value: [0-9][a-f]*
            name = f"{int(name[1:], 16):#x}"
            is_parsed = True

        elif space_shortcut in r"%o":  # IPTR_PROCESSOR
            # %: register
            # o: other
            # ???
            # name == "o0x" offset
            # name == "0x{offset:0{size}x}"
            # name == "0x{offset:0{size}x}+{\d+}"
            name = name[1:]
            is_parsed = True

        elif space_shortcut == "s":  # IPTR_SPACEBASE
            # TODO
            ...

        elif space_shortcut == "u":  # IPTR_INTERNAL
            # name = "u" addr_space
            name = parse_addr_space(name[1:])

        elif space_shortcut == "f" and name.startswith("ffunc_"):  # IPTR_FSPEC - cf. FspecSpace::printRaw
            # name == "f" function_name -- this case is not handled here because
            #                              of ambiguity...
            # name == "ffunc_" function_addr
            name = name[1:]
            is_parsed = True

        elif space_shortcut == "j" and name[1] == "{" and name[-1] == "}":  # IPTR_JOIN - cf. JoinSpace::printRaw
            # name == "j{" addr_space ":" sznum "}"
            # name == "j{" addr_space ("," addr_space)+ "}"
            # addr_space: "0x" [0-9a-f]{1,2,3,4,6} ("+" [1-9][0-9]*)?

            # there is no "," in addr_space, so we can split on that
            spaces = name[2:-1].split(",")
            if len(spaces) == 1:
                assert ":" in name, name
                sznum = int(name[name.index(":") + 1:-1], 10)
            else:
                sznum = "unknown"

            desc = []
            for space in spaces:
                addr = parse_addr_space(space)
                assert addr is not None, (name, space)
                desc.append(addr)

            name = f"JOIN {desc} size={sznum}"
            is_parsed = True

        elif space_shortcut == "i":  # IPTR_IOP
            # IopSpace::printRaw
            # name == "i" pc_raw (":" uniq)?
            # name == "icode_" branch_addr_shortcut branch_addr
            # pc_raw: "invalid_addr" | addr_space
            # uniq: int

            if name.startswith("icode_"):
                # "icode_" branch_addr_shortcut branch_addr
                # TODO: Parse this
                name = f"IOP branch {name}"
            else:
                # "i" pc_raw (":" uniq)?
                target_str = name[1:]

                try:
                    pc_raw, uniq_str = target_str.split(":")
                except ValueError:
                    pc_raw, uniq_str = target_str, "-1"

                if pc_raw == "invalid_addr":
                    pc = None
                else:
                    pc = parse_addr_space(pc_raw)
                    assert pc is not None, (name, pc_raw)
                    assert pc.endswith("+0"), pc
                    pc = int(pc[:-len("+0")], 16)

                uniq = int(uniq_str, 16)
                name = f"IOP {pc}:{uniq}"
                seq_num = (pc, uniq)
            is_parsed = True

        if not is_parsed:
            # The name is something that could not be parsed
            space_shortcut = "?"
            name = name

        return Identifier(is_free, is_input, is_written, size, seq_num, space_shortcut, name)

    def is_constant(self) -> bool:
        return self._space_shortcut == "#"

    def __eq__(self, other) -> bool:
        """
        Basically copied from Varnode::operator== in 'varnode.cc'
        """
        if not isinstance(other, Identifier): return NotImplemented
        if self is other: return True
        if self._space_shortcut == "#": return False  # Constants are always unique

        if self._space_shortcut != other._space_shortcut: return False
        if self._name != other._name: return False
        if self._size != other._size: return False
        if self._is_input != other._is_input: return False
        if self._is_written != other._is_written: return False
        # HACK: Only comparing self._seq_num[0] because the diffs don't tell us
        # when the 'time' (self._seq_num[1]) of an identifier is changed.
        # Issue: https://github.com/NationalSecurityAgency/ghidra/issues/4963
        if self._is_written and not self._is_input and self._seq_num[0] != other._seq_num[0]: return False

        return True

    def __hash__(self) -> int:
        # HACK: Only using self._seq_num[0] because the diffs don't tell us
        # when the 'time' (self._seq_num[1]) of an identifier is changed.
        # Issue: https://github.com/NationalSecurityAgency/ghidra/issues/4963
        return (
            self._space_shortcut, self._name, self._size, self._is_input,
            self._is_written, self._seq_num[0] if self._is_written and not self._is_input else -1
        ).__hash__()

    def __str__(self) -> str:
        return f"ID({self._space_shortcut}{self._name} @ {self._seq_num}{' free' if self._is_free else ''}{' input' if self._is_input else ''})"

    def get_node_name(self) -> str:
        return f"{self._space_shortcut}{self._name}"

    def get_color_name(self) -> str:
        if self._is_input:
            return "yellow"
        if self.is_constant():
            return "gray"
        return "green"

    def get_tooltip_text(self) -> typing.Optional[str]:
        return self.__str__()

@dataclass(frozen=True)
class InstructionReference:
    _target: Identifier  # The target operation

    @staticmethod
    def from_raw(name: str) -> "InstructionReference":
        ident = Identifier.from_raw(name, no_size=True)
        assert ident._space_shortcut == "i", (name, ident)
        assert ident._size is None, (name, ident)
        return InstructionReference(ident)

    def get_node_name(self) -> str:
        return f"REF {self._target}"

    def get_color_name(self) -> str:
        return "blue"

    def get_tooltip_text(self) -> typing.Optional[str]:
        return None

@dataclass(frozen=True)
class Operation:
    # the line that produced this operation
    _line: str
    # the address of this operation
    _addr: tuple[int, int]
    # whether the thing is empty
    _is_empty: bool
    # the CPUI name of this operation
    _op: str
    # a sequence of inputs
    _in: typing.Sequence[Identifier | AddrSpace | InstructionReference | None]
    # the output identifier
    _out: typing.Optional[Identifier]

    @staticmethod
    def from_raw(line: bytes) -> "Operation":
        full_line = line.decode("utf-8").strip(" ")

        # eg. 0x800fb41c:22: u0x1000000d:1(0x800fb41c:22) = u0x10000012:1(0x800fb41c:61)
        parts = full_line.split(" ")
        assert parts[0].endswith(":"), line
        addr = tuple(map(lambda n: int(n, 16), parts[0][:-1].split(":")))
        num_parts = len(parts)

        _in: typing.Sequence[Identifier | AddrSpace | InstructionReference | None] = []
        _op: typing.Optional[str] = None

        # might be ** (empty)
        is_empty = parts[1] == "**" and num_parts == 2

        if is_empty:
            return Operation(full_line, addr, True, "", _in, None)

        if parts[1].startswith("*("):  # TypeOpStore
            assert parts[2] == "=", parts

            in0_space_name, in1 = parts[1][2:-1].split(",")

            return Operation(full_line, addr, False, "STORE", [
                AddrSpace.from_raw(in0_space_name),
                Identifier.from_raw(in1),
                Identifier.from_raw(parts[3]),
            ], None)

        if parts[1] in ("goto", "switch") and num_parts == 3:  # TypeOpBranch, TypeOpBranchind
            op = {"goto": "BRANCH", "switch": "BRANCHIND"}[parts[1]]
            return Operation(full_line, addr, False, op, [Identifier.from_raw(parts[2])], None)

        if parts[1] == "goto":  # TypeOpCbranch
            # goto <in0> if (<in1> == 0)
            assert parts[3] == "if" and parts[5] in ("==", "!=") and parts[6] == "0)", parts

            _in = [Identifier.from_raw(parts[2]), Identifier.from_raw(parts[4][1:])]
            return Operation(full_line, addr, False, "CBRANCH", _in, None)

        if parts[1] == "return" or parts[1].startswith("return("):  # TypeOpReturn
            if "(" in parts[1]:
                # return(<in0>) <in1>,<in2>,...
                in0 = Identifier.from_raw(parts[1][:-1].split("(", 1)[1])

                if num_parts == 2:
                    _in = [in0]
                else:
                    _in = [in0] + [Identifier.from_raw(i) for i in parts[2].split(",")]

            return Operation(full_line, addr, False, "RETURN", _in, None)

        if parts[1] in ("call", "callind") or (num_parts >= 4 and parts[3] in ("call", "callind")):  # TypeOpCall, TypeOpCallind

            has_out = parts[1] not in ("call", "callind")
            call_part = parts[1] if not has_out else parts[3]
            function = parts[2] if not has_out else parts[4]

            # How do we even differentiate between call fName(<addr>) [no args]
            # and fName(<varnode>) [has args]?
            has_args = "," in function  # BUG: fdBc_c::isFoot:8(free)(r3(0x800b86ec:204)) is not detected as having args

            _op = "CALL" if call_part == "call" else "CALLIND"

            if has_out:
                _out = Identifier.from_raw(parts[1])
                assert parts[2] == "=", parts
            else:
                _out = None

            if has_args:
                split_idx = find_matching_open_paren_to_final_close_paren(function)
                name, args = function[:split_idx], function[split_idx:][1:-1]

                func_name = Identifier.from_raw(name)
                _in = [func_name] + [Identifier.from_raw(i) for i in args.split(",")]
            else:
                _in = [Identifier.from_raw(function)]

            return Operation(full_line, addr, False, _op, _in, _out)

        if parts[1] == "syscall" or (num_parts >= 4 and parts[3] == "syscall"):  # TypeOpCallother
            _op = "CALLOTHER"
            has_out = parts[3] == "syscall"
            function = parts[4] if has_out else parts[2]
            has_args = "," in function  # BUG: fName(arg) is not detected as having args

            if has_out:
                _out = Identifier.from_raw(parts[1])
                assert parts[2] == "=", parts
            else:
                _out = None

            if has_args:
                split_idx = find_matching_open_paren_to_final_close_paren(function)
                name, args = function[:split_idx], function[split_idx:][1:-1]

                func_name = Identifier.from_raw(name)
                _in = [func_name] + [Identifier.from_raw(i) for i in args.split(",")]
            else:
                _in = [Identifier.from_raw(function)]

            return Operation(full_line, addr, False, _op, _in, _out)

        if parts[1] == "segmentop" or (num_parts >= 4 and parts[3] == "segmentop"):  # TypeOpSegment
            _op = "SEGMENTOP"
            has_out = parts[3] == "segmentop"
            function = parts[4] if has_out else parts[2]

            if has_out:
                _out = Identifier.from_raw(parts[1])
                assert parts[2] == "=", parts
            else:
                _out = None

            _in = [Identifier.from_raw(i) for i in function[len("segmentop("):-1].split(",")]
            return Operation(full_line, addr, False, _op, _in, _out)

        # CPOOLREF and NEW are 'Pseudo P-CODE Operations' and are documented
        # here:
        # https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/GhidraDocs/languages/html/pseudo-ops.html

        # USERDEFINED is also a pseudo P-CODE op, but its ::printRaw method can
        # output pretty much anything, so it's much harder to parse. I just
        # assume it is the only thing that reaches here that has only 2 parts.

        if parts[1].startswith("cpoolref_") or (num_parts >= 4 and parts[3].startswith("cpoolref_")):  # TypeOpCpoolref
            # Retrieves a constant from the constant pool
            _op = "CPOOLREF"

            has_out = parts[3].startswith("cpoolref_")
            function = parts[3] if has_out else parts[1]

            if has_out:
                _out = Identifier.from_raw(parts[1])
                assert parts[2] == "=", parts
            else:
                _out = None

            _in = [Identifier.from_raw(i) for i in function.split("(", 1)[1][:-1].split(",")]
            _in.insert(1, None)  # BUG? input 1 (type of value to return) is not printed?
            return Operation(full_line, addr, False, _op, _in, _out)

        if parts[1].startswith("new(") or (num_parts >= 4 and parts[3].startswith("new(")):  # TypeOpNew
            _op = "NEW"
            has_out = parts[3].startswith("new(")
            function = parts[4] if has_out else parts[2]

            if has_out:
                _out = Identifier.from_raw(parts[1])
                assert parts[2] == "=", parts
            else:
                _out = None

            _in = [Identifier.from_raw(i) for i in function[len("new("):-1].split(",")]

            return Operation(full_line, addr, False, _op, _in, _out)

        if num_parts == 2:
            # A user-defined operation. Pretend it's an empty line
            print(f"Ignoring user-defined operation: {parts[1]!r}")
            return Operation(full_line, addr, True, "", _in, None)

        assert num_parts > 2 and parts[2] == "=", parts

        # MULTIEQUAL, INDIRECT, PTRADD, PTRSUB, CAST and INSERT are 'Additional
        # P-CODE Operations' and are documented here:
        # https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/GhidraDocs/languages/html/additionalpcode.html

        # PTRSUB is parsed as a TypeOpBinary, because its ::printRaw output makes
        # it seem like one. For the same reason, INSERT is parsed like a
        # TypeOpFunc.

        _out = Identifier.from_raw(parts[1])

        if num_parts >= 6 and parts[4] == "?" and num_parts % 2 == 0:  # TypeOpMulti
            _op = "MULTIEQUAL"
            _in = [Identifier.from_raw(i) for i in parts[3::2]]
            return Operation(full_line, addr, False, _op, _in, _out)

        if parts[3] == "[create]" or (num_parts >= 5 and parts[4] == "[]"):  # TypeOpIndirect
            _op = "INDIRECT"

            if parts[3] == "[create]":
                # <out> = [create] <in1>
                # While in0 is not specified, from the documentation, we know
                # that it is a constant varnode with value 0.
                _in = [Identifier.from_raw("#0x0"), InstructionReference.from_raw(parts[4])]
            else:
                # <out> = <in0> [] <in1>
                _in = [Identifier.from_raw(parts[3]), InstructionReference.from_raw(parts[5])]

            return Operation(full_line, addr, False, _op, _in, _out)

        if parts[3] == "(cast)":  # TypeOpCast
            return Operation(full_line, addr, False, "CAST", [Identifier.from_raw(parts[4])], _out)

        if parts[3].startswith("*("):  # TypeOpLoad
            _op = "LOAD"

            in0_space_name, in1 = parts[3][2:-1].split(",")
            _in = [
                AddrSpace.from_raw(in0_space_name),
                Identifier.from_raw(in1),
            ]
            return Operation(full_line, addr, False, _op, _in, _out)

        if num_parts == 6 and parts[4] == "+" and "(*" in parts[5]:  # TypeOpPtradd
            split_idx = find_matching_open_paren_to_final_close_paren(parts[5])
            assert parts[5][split_idx:].startswith("(*"), f"Incorrect PTRADD: {parts}\n  {full_line}"
            a, b = parts[5][:split_idx], parts[5][split_idx + 2:-1]
            _in = [Identifier.from_raw(parts[3]), Identifier.from_raw(a), Identifier.from_raw(b)]
            return Operation(full_line, addr, False, "PTRADD", _in, _out)

        # Parse the base classes that have a set ::printRaw format
        if num_parts == 4:  # TypeOpFunc / COPY
            op_trans_dict: dict[str, str] = {
                "NAN": "FLOAT_NAN",
                "ABS": "FLOAT_ABS",
                "SQRT": "FLOAT_SQRT",
                "INT2FLOAT": "FLOAT_INT2FLOAT",
                "FLOAT2FLOAT": "FLOAT_FLOAT2FLOAT",
                "TRUNC": "FLOAT_TRUNC",
                "CEIL": "FLOAT_CEIL",
                "FLOOR": "FLOAT_FLOOR",
                "ROUND": "FLOAT_ROUND",
                "INSERT": "INSERT",
                "EXTRACT": "EXTRACT",
                "POPCOUNT": "POPCOUNT",
                "COUNTLEADINGZEROS": "COUNTLEADINGZEROS",
                "COUNTLEADINGONES": "COUNTLEADINGONES",
            }

            _op = None
            if "(" in parts[3]:
                op_name, args = parts[3].split("(", 1)

                if op_name.startswith("ZEXT"):
                    _op = f"INT_ZEXT({op_name[4]}, {op_name[5]})"
                elif op_name.startswith("SEXT"):
                    _op = f"INT_SEXT({op_name[4]}, {op_name[5]})"
                elif op_name.startswith("CARRY"):
                    _op = f"INT_CARRY({op_name[5:]})"
                elif op_name.startswith("SCARRY"):
                    _op = f"INT_SCARRY({op_name[6:]})"
                elif op_name.startswith("SBORROW"):
                    _op = f"INT_SBORROW({op_name[7:]})"
                elif op_name.startswith("CONCAT"):
                    _op = f"PIECE({op_name[6]}, {op_name[7]})"
                elif op_name.startswith("SUB"):
                    _op = f"SUBPIECE({op_name[3]}, {op_name[4]})"
                elif op_name in op_trans_dict:
                    _op = op_trans_dict[op_name]

            # set inputs
            if _op is None:
                _op = "COPY"
                _in = [Identifier.from_raw(parts[3])]
            else:
                assert args[-1] == ")", (args, parts)
                _in = [Identifier.from_raw(i) for i in args[:-1].split(",")]

            return Operation(full_line, addr, False, _op, _in, _out)

        if num_parts == 5:  # TypeOpUnary
            _op = {
                "-": "INT_2COMP",  # or FLOAT_NEG
                "~": "INT_NEGATE",
                "!": "BOOL_NEGATE",
                # The operators below are unofficial
                "f-": "FLOAT_NEG",
            }[parts[3]]

            _in = [Identifier.from_raw(parts[4])]
            return Operation(full_line, addr, False, _op, _in, _out)

        if num_parts == 6:  # TypeOpBinary / TypeOpPtrsub
            _op = {
                "==": "INT_EQUAL",  # or FLOAT_EQUAL
                "!=": "INT_NOTEQUAL",  # or FLOAT_NOTEQUAL
                "<": "INT_LESS",  # or INT_SLESS or FLOAT_LESS
                "<=": "INT_LESSEQUAL",  # or INT_SLESSEQUAL or FLOAT_LESSEQUAL
                "+": "INT_ADD",  # or FLOAT_ADD
                "-": "INT_SUB",  # or FLOAT_SUB
                "^": "INT_XOR",
                "&": "INT_AND",
                "|": "INT_OR",
                "<<": "INT_LEFT",
                ">>": "INT_RIGHT",
                "s>>": "INT_SRIGHT",
                "*": "INT_MULT",  # or FLOAT_MULT
                "/": "INT_DIV",  # or INT_SDIV or FLOAT_DIV
                "%": "INT_REM",  # or INT_SREM
                "^^": "BOOL_XOR",
                "&&": "BOOL_AND",
                "||": "BOOL_OR",
                "->": "PTRSUB",
                # The operators below are unofficial
                "f==": "FLOAT_EQUAL",
                "f!=": "FLOAT_NOTEQUAL",
                "s<": "INT_SLESS",
                "f<": "FLOAT_LESS",
                "s<=": "INT_SLESSEQUAL",
                "f<=": "FLOAT_LESSEQUAL",
                "f+": "FLOAT_ADD",
                "f-": "FLOAT_SUB",
                "f*": "FLOAT_MULT",
                "s/": "INT_SDIV",
                "f/": "FLOAT_DIV",
                "s%": "INT_SREM",
            }[parts[4]]

            _in = [Identifier.from_raw(parts[3]), Identifier.from_raw(parts[5])]
            return Operation(full_line, addr, False, _op, _in, _out)

        raise ValueError(f"Unparsable printRaw output: {parts}")

    def __str__(self) -> str:
        if self._is_empty:
            return f"{self._addr}: **"

        out = f"{self._addr}: "

        if self._out is not None:
            out += f"{self._out} <- "

        return out + f"{self._op} [ {' , '.join(str(x) for x in self._in)} ]"

    def __hash__(self) -> int:
        if self._is_empty:
            return ().__hash__()
        return (self._out, self._op, *self._in).__hash__()

    def get_node_name(self) -> str:
        return self._op

    def get_color_name(self) -> str:
        return "red"

    def get_tooltip_text(self) -> typing.Optional[str]:
        return self.__str__()
