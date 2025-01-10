from binaryninja import *


def make_simple_call_graph(graph_view,root_node,root_function,nodes):
    for xref_to_func in bv.get_callers(root_function.start):
        if not xref_to_func.function.name.startswith("sub") and not xref_to_func.function.name.startswith("j_sub"):
            print(f"[*] Got to function with non-standard name: {xref_to_func.function.name}")
        if xref_to_func.function.name not in nodes:
            nodes.append(xref_to_func.function.name)
            xref_graph_node = FlowGraphNode(graph_view)
            xref_graph_node.lines = [
                DisassemblyTextLine(
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.CodeSymbolToken,
                            xref_to_func.function.name,
                            xref_to_func.function.start
                        )
                    ]
                )
            ]
            graph_view.append(xref_graph_node)
            root_node.add_outgoing_edge(BranchType.UnconditionalBranch,xref_graph_node)
            make_simple_call_graph(graph_view,xref_graph_node,xref_to_func.function,nodes.copy())

section_list = [(s_name, bv.sections[s_name].start,bv.sections[s_name].end) for s_name in bv.sections]
section_choice = get_large_choice_input("Generate Graph", "Select Section", [f"{s[0]:<35} {hex(s[1])} - {hex(s[2])}" for s in section_list])
if section_choice != None:
    graph_view = FlowGraph()
    start_addr = section_list[section_choice][1]
    end_addr = section_list[section_choice][2]
    graph_name = f"{section_list[section_choice][0]} Call Graph"
    for addr in range(start_addr,end_addr,bv.address_size):
        data_variable = bv.get_data_var_at(addr)
        if data_variable:
            current_graph_node = FlowGraphNode(graph_view)
            if data_variable.name:
                name = data_variable.name
            else:
                name = hex(data_variable.address)
            current_graph_node.lines = [
                DisassemblyTextLine(
                [
                    InstructionTextToken(
                        InstructionTextTokenType.CodeSymbolToken,
                        name,
                        data_variable.address
                    )
                ]
            )]
            graph_view.append(current_graph_node)
            marked_funcs = []
            for code_ref in data_variable.code_refs:
                if code_ref.function.name in marked_funcs:
                    continue
                marked_funcs.append(code_ref.function.name)
                nodes = []
                xref_graph_node = FlowGraphNode(graph_view)
                xref_graph_node.lines = [
                    DisassemblyTextLine(
                    [
                        InstructionTextToken(
                            InstructionTextTokenType.CodeSymbolToken,
                            code_ref.function.name,
                            code_ref.function.start
                        )
                    ]
                    )
                ]
                graph_view.append(xref_graph_node)
                current_graph_node.add_outgoing_edge(BranchType.UnconditionalBranch,xref_graph_node)
                make_simple_call_graph(graph_view,xref_graph_node,code_ref.function,nodes)

    graph_view.layout_and_wait()
    graph_view.show(graph_name)

