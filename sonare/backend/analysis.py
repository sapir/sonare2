from collections import defaultdict
from sortedcontainers import SortedList
import networkx as nx
import capstone


def make_flow_graph(opcodes):
    valid_addresses = {opcode["address"] for opcode in opcodes}

    flow_graph = nx.DiGraph()

    for opcode in opcodes:
        flow_graph.add_node(opcode["address"])
        flow_graph.add_edges_from(
            (opcode["address"], f) for f in opcode["flow"]
            if f in valid_addresses)

    return flow_graph


def make_block_graph(opcodes):
    flow_graph = make_flow_graph(opcodes)

    opcodes_by_address = {opcode["address"]: opcode for opcode in opcodes}

    def address_follows(address, opcode):
        return address == opcode["address"] + opcode["size"]

    block_starts = {
        address for address in flow_graph
        if flow_graph.in_degree(address) != 1 or
        flow_graph.out_degree(flow_graph.predecessors(address)[0]) != 1 or
        not address_follows(
            address, opcodes_by_address[flow_graph.predecessors(address)[0]])
    }

    # now tag nodes to blocks. start by tagging the block start nodes, then
    # copy the tags forward along edges.
    node_blocks = {address: address for address in block_starts}
    for a, b in nx.edge_dfs(flow_graph):
        if b not in block_starts:
            node_blocks[b] = node_blocks[a]

    # if we didn't reach all nodes, above algorithm is broken.
    assert set(node_blocks.keys()) == set(flow_graph.nodes())

    # invert the tag dict - find the nodes comprising each block.
    block_nodes = defaultdict(SortedList)
    for address, block in node_blocks.items():
        block_nodes[block].append(address)

    # now make the block graph!
    block_graph = nx.DiGraph()
    for block, nodes in block_nodes.items():
        block_graph.add_node(block, opcodes=list(nodes))

        next_blocks = flow_graph.successors(nodes[-1])
        block_graph.add_edges_from(
            (block, next_block) for next_block in next_blocks)

    return block_graph


def block_graph_to_dict(block_graph):
    def make_block_dict(address):
        return {
            "address": address,
            "flow": block_graph.successors(address),
            "opcodes": block_graph.node[address]["opcodes"],
        }

    return list(map(make_block_dict, block_graph.nodes()))


def analyze_func(backend, func):
    # TODO: redo function analysis when appropriate
    if func.attrs.get("blocks"):
        return

    print(f"analyzing {func.name} @ {func.start:#x}, size {func.size:#x}")
    arch = backend.get_arch()

    func_mode = func.attrs.get("mode")
    opcodes = list(arch.analyze_opcodes(func.start, func.end, mode=func_mode))

    for opcode in opcodes:
        backend.asm_lines.upsert(
            opcode["address"],
            opcode["address"] + opcode["size"],
            insn_name=opcode["insn_name"],
            text=opcode["text"],
            flow=opcode["flow"],
            operands=opcode["operands"],
            tokens=opcode["tokens"],
        )

    block_graph = make_block_graph(opcodes)
    func.attrs["blocks"] = block_graph_to_dict(block_graph)

    backend.functions.update_obj(func)


def analyze_all(backend):
    for func in backend.functions.iter_by_addr():
        analyze_func(backend, func)
