import networkx
import pwn

from dataclasses import dataclass
import typing
import traceback
import itertools

def find_runs(haystack: str, needles: list[str]):
    """
    A generator that yields 3-tuples (needle_type, start_idx, end_idx) for every
    run of consecutive needles of the same type in the string 'haystack'.
    Assumes all needles are 1 character long.
    """
    idx = 0

    while True:
        next_needles = {needle: haystack.find(needle, idx) for needle in needles}
        try:
            needle_type = min([k for k in next_needles.keys() if next_needles[k] != -1], key=next_needles.get)
        except ValueError:
            # no needles left in haystack
            break

        needle_idx = next_needles[needle_type]

        for needle_end in range(needle_idx, len(haystack)):
            if haystack[needle_end] != needle_type:
                break

        yield (needle_type, needle_idx, needle_end)
        idx = needle_end

def html_escape(text: str) -> str:
    """
    Returns the HTML-escaped version of a string. This function replaces the
    characters '<', '>' and '&' with their respective HTML escape sequences.
    Assumes the input does not contain any HTML escape sequences.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def html_get_nth_char_idx(target_str: str, n: int) -> int:
    """
    Returns the index of the n'th character in the target string, counting HTML
    escape sequences as a single character.
    Raises ValueError if the string contains fewer than n characters
    """
    target_len = len(target_str)
    i = 0
    while i < target_len:
        if n == 0:
            return i

        if target_str[i] == "&":  # html escape sequences, skip until ';'
            i = target_str.find(";", i)

        i += 1
        n -= 1

    raise ValueError(f"Supplied index {n} out of range for string {target_str}")

def colourise_diff(diff: list[str]) -> str:
    """
    This function adds markup to the input string, which is assumed to be a diff
    as produced by difflib. The returned string contains a HTML description of a
    table with the changed parts of the diff highlighted.
    """
    table_rows = []

    for line in diff:
        prefix, line = line[:2], line[2:]
        escaped_line = html_escape(line)

        if prefix == "  ":
            table_rows.append(f"<td><tt>{escaped_line}</tt></td>")
        elif prefix == "+ ":
            table_rows.append(f"<td bgcolor='#e6ffec'><tt>{escaped_line}</tt></td>")
        elif prefix == "- ":
            table_rows.append(f"<td bgcolor='#ffebe9'><tt>{escaped_line}</tt></td>")
        elif prefix == "? ":
            offset = len("<td bgcolor='#ffebe9'><tt>")
            prev = table_rows.pop()
            prev_is_add = prev.startswith("<td bgcolor='#e6ffec'>")

            for run_type, high_start, high_end in find_runs(line, ("^", "-", "+")):
                bg_col = "#abf2bc" if prev_is_add else "#ffc0c0"
                chunk_start = html_get_nth_char_idx(prev, offset + high_start)
                chunk_end = html_get_nth_char_idx(prev, offset + high_end)
                prev = prev[:chunk_start] + f"<span style='background-color:{bg_col}'>" + prev[chunk_start:chunk_end] + "</span>" + prev[chunk_end:]
                offset += len(f"<span style='background-color:{bg_col}'></span>")

            table_rows.append(prev)
        else:
            print(f"Unknown prefix {prefix!r}, skipping line...")

    return "<table width='100%'><tr>" + "</tr><tr>".join(table_rows) + "</tr></table>"

def get_decompile_data(decomp_path: str, ghidra_path: str, xml_path: str, func_name: str, extra_paths: list[str]) -> list[tuple[bytes, bytes]]:
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

    with pwn.process(command, env={"SLEIGHHOME": ghidra_path}) as p:
        p.sendlineafter(b"[decomp]> ", f"restore {xml_path}".encode("utf-8"))
        p.readline()

        _restore_resp = p.readuntil(b"[decomp]> ")
        if b"successfully loaded:" not in _restore_resp:
            raise ValueError(f"Unexpected response to 'restore {xml_path}': {_restore_resp.decode('utf-8')!r}")

        p.sendline(b"load function " + func_name.encode("utf-8"))
        p.readline()

        _load_resp = p.readuntil(b"[decomp]> ").decode("utf-8")
        # -1 is used as index to select the first element of the split if the
        # function is not namespaced
        bare_func_name = func_name.rsplit("::", 1)[-1]
        if not _load_resp.startswith(f"Function {bare_func_name}: "):
            raise ValueError(f"Unexpected response to 'load function {func_name}': {_load_resp!r}")

        p.sendline(b"trace address")
        p.readline()

        _range_resp = p.readuntil(b"[decomp]> ", drop=True)
        if _range_resp != b"OK (1 ranges)\n":
            raise ValueError(f"Unexpected response to 'trace address': {_range_resp.decode('utf-8')!r}")

        p.sendline(b"trace break 0")
        p.readline()  # b'trace break 0\n'

        _break_resp = p.readuntil(b"[decomp]> ", drop=True)
        if _break_resp != b"":
            raise ValueError(f"Unexpected response to 'trace break 0': {_break_resp.decode('utf-8')!r}")

        ## Start the decompilation
        pcodes = []
        p.sendline(b"print raw")
        p.readline()
        pcodes.append((b"Raw P-CODE", p.readuntil(b"[decomp]> ", drop=True)))

        p.sendline(b"decompile")
        p.readline()  # b'decompile\n'
        p.readline()  # b'Decompiling {function name}\n'

        # Step through the decompilation process, one rule at a time
        done = False
        while not done:
            rule_type = p.readline()
            rule_name = rule_type.split(b' ', 2)[-1].strip()

            pcode_changes = p.readuntil(b'[decomp]> ', drop=True)
            if b'\n\nDEBUG ' in pcode_changes:
                # Multiple rules were executed. Unfortunately, it will be hard
                # to isolate the changes made by individual rules, but we can at
                # least indicate which rules are responsible for the combined
                # changes, by having multiple names, separated by '&'.
                get_name = lambda c: c.split(b'\n', 1)[0].split(b' ', 2)[-1].strip()
                rule_name += b''.join([
                    b' & ' + get_name(chunk)
                    for chunk in pcode_changes.split(b'\n\n')[1:]
                    if not chunk.startswith(b'Break at ')
                ])

            if not pcode_changes:
                # No changes were made, exit immediately
                break

            # Maybe the decompilation was done after these changes were made...
            done = pcode_changes.endswith(b'Decompilation complete\n')

            # The decompiler has been paused - get the current pcode state and
            # set the next breakpoint.
            p.send(
                b"trace enable\n"
                b"print raw\n"
                b"continue\n"
            )
            p.readuntil(b"[decomp]> ")
            p.readline()  # b'print raw\n'

            pcode = p.readuntil(b"[decomp]> ", drop=True)
            pcodes.append((rule_name, pcode))

            p.readline()  # b'continue\n'

    return pcodes

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

def layout_algorithm(graph: networkx.DiGraph, layout_prog='dot') -> dict['Node', tuple[float, float]]:
    # Create a mapping from node objects to unique string identifiers
    node_to_str = {node: str(i) for i, node in enumerate(graph.nodes())}
    str_to_node = {v: k for k, v in node_to_str.items()}

    # Create a new graph with string identifiers
    quoted_graph = networkx.DiGraph()
    quoted_graph.add_nodes_from((node_to_str[node] for node in graph.nodes()))
    quoted_graph.add_edges_from(((node_to_str[start], node_to_str[end]) for start, end in graph.edges()))

    # Give nodes a size of 1, to reduce overlapping nodes in the final layout
    networkx.set_node_attributes(quoted_graph, {node_to_str[node]: {'height': 1, 'width': 1} for node in graph.nodes()})

    # Use Graphviz to get the layout
    pos = networkx.nx_pydot.pydot_layout(quoted_graph, prog=layout_prog)

    # Map string identifiers back to original nodes and flip y-axis
    return {str_to_node[n]: (x, -y) for n, (x, y) in pos.items()}

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
                    print(f"Warning: Unexpected parenthesised group at the end of varnode: {name!r} - {part[1:-1]}")
                    traceback.format_exc()

            name = name[:start_idx]

        # Then check for size modifier - make sure to not misidentify the size
        # if there is a colon in the name.
        size = None
        if not no_size:
            if ":" in name:
                name, size_ = name.rsplit(":", 1)
                try:
                    size = int(size_, 16)
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
        if self._is_written and not self._is_input and self._seq_num != other._seq_num: return False

        return True

    def __hash__(self) -> int:
        return (
            self._space_shortcut, self._name, self._size, self._is_input,
            self._is_written, self._seq_num if self._is_written and not self._is_input else -1
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
        ident = Identifier.from_raw(name, no_size=name.count(':') != 2)
        assert ident._space_shortcut == "i", (name, ident)
        assert name.count(':') == 2 or ident._size is None, (name, ident)
        return InstructionReference(ident)

    def get_node_name(self) -> str:
        return f"INSTRUCTION REF"

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

            # Try to differentiate between call fName(<addr>) and fName(free)
            split_idx = find_matching_open_paren_to_final_close_paren(function)
            has_args = function[split_idx:] not in ('(free)', '(i)')

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

        # USERDEFINED is also a pseudo P-CODE op, but its ::printRaw method can
        # output pretty much anything, so it's much harder to parse. I just
        # assume it is the only thing that reaches here that has only 2 parts.
        if num_parts == 2:
            # Attempt to parse the operation as a function call. Example:
            #   parts = ['0x020f83fc:45:', 'callindr0(0x020f83e8:3f)(r3(0x020f83e0:3b),#0x10026450,#0x1)']
            function = parts[1]

            # Try to differentiate between call fName(<addr>) and fName(free)
            split_idx = find_matching_open_paren_to_final_close_paren(function)
            has_args = function[split_idx:] not in ('(free)', '(i)')

            if has_args:
                name, args = function[:split_idx], function[split_idx:][1:-1]

                func_name = Identifier.from_raw(name)
                _in = [func_name] + [Identifier.from_raw(i) for i in args.split(',')]
            else:
                _in = [Identifier.from_raw(function)]

            return Operation(full_line, addr, False, 'USERDEFINED', _in, None)

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

                def disambiguate_numbers(s: str) -> tuple[str, str]:
                    numbers = op_name[6:]
                    if len(s) == 2:
                        return (s[0], s[1])

                    # This is an ugly hack that guesses that one of the two
                    # numbers is a power of two. That seems to disambiguate
                    # correctly most of the time, but there's no guarantee
                    # it works. It'd be really great if the numbers were not
                    # printed in an ambiguous way...
                    if len(s) == 3:
                        n = int(s[:2])
                        if n & (n - 1) == 0 and n != 0:
                            return (s[:2], s[2])
                        return (s[0], s[-2:])

                    if len(s) == 4:
                        return (s[:2], s[2:])

                    raise ValueError(f"Unexpected numbers string: {s!r}")

                if op_name.startswith("ZEXT"):
                    numbers = disambiguate_numbers(op_name[4:])
                    _op = f"INT_ZEXT({numbers[0]}, {numbers[1]})"
                elif op_name.startswith("SEXT"):
                    numbers = disambiguate_numbers(op_name[4:])
                    _op = f"INT_SEXT({numbers[0]}, {numbers[1]})"
                elif op_name.startswith("CARRY"):
                    _op = f"INT_CARRY({op_name[5:]})"
                elif op_name.startswith("SCARRY"):
                    _op = f"INT_SCARRY({op_name[6:]})"
                elif op_name.startswith("SBORROW"):
                    _op = f"INT_SBORROW({op_name[7:]})"
                elif op_name.startswith("CONCAT"):
                    numbers = disambiguate_numbers(op_name[6:])
                    _op = f"PIECE({numbers[0]}, {numbers[1]})"
                elif op_name.startswith("SUB"):
                    numbers = disambiguate_numbers(op_name[3:])
                    _op = f"SUBPIECE({numbers[0]}, {numbers[1]})"
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
