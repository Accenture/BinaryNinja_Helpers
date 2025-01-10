from binaryninja import *

dumb_graph_nodes = []

class DumbGraphNode:
    def __init__(self):
        self.parent_node = None
        self.child_nodes = []
        self.text = None
        self.graph_view_parent = None
        self.graph_view_node = None


def make_simple_call_graph(root_node,root_function,nodes):
    for xref_to_func in bv.get_callers(root_function.start):
        if xref_to_func.function.name not in nodes:
            nodes.append(xref_to_func.function.name)

            new_node = DumbGraphNode()
            new_node.parent_node = root_node
            root_node.child_nodes.append(new_node)
            new_node.text = xref_to_func.function.name
            new_node.graph_view_parent = root_node.graph_view_node
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
            new_node.graph_view_node = xref_graph_node
            dumb_graph_nodes.append(new_node)
            #graph_view.append(xref_graph_node)
            #root_node.add_outgoing_edge(BranchType.UnconditionalBranch,xref_graph_node)
            make_simple_call_graph(new_node,xref_to_func.function,nodes.copy())

def connect_graph_names_only(graph_view):
    mapped_parents = []
    counter = 0
    for node in dumb_graph_nodes:
        if not node.text.startswith("sub_") and not node.text.startswith("j_sub_"):
            current_node = node
            graph_view.append(current_node.graph_view_node)
            while current_node.parent_node:
                graph_view.append(current_node.graph_view_parent)
                current_node.graph_view_parent.add_outgoing_edge(BranchType.UnconditionalBranch,current_node.graph_view_node)
                if current_node.parent_node in mapped_parents:
                    break
                mapped_parents.append(current_node.parent_node)
                current_node = current_node.parent_node

def connect_everything(graph_view):
    for node in dumb_graph_nodes:
        graph_view.append(node.graph_view_node)
        if node.parent_node:
            node.graph_view_parent.add_outgoing_edge(BranchType.UnconditionalBranch,node.graph_view_node)
        

section_list = [(s_name, bv.sections[s_name].start,bv.sections[s_name].end) for s_name in bv.sections]
section_choice = get_large_choice_input("Generate Graph", "Select Section", [f"{s[0]:<35} {hex(s[1])} - {hex(s[2])}" for s in section_list])
if section_choice != None:
    type_choice = interaction.get_choice_input("What type of graph do you want?","Graph Type", ["Complete graph","Branches with named functions only"])
    if type_choice != None:
        graph_view = FlowGraph()
        start_addr = section_list[section_choice][1]
        end_addr = section_list[section_choice][2]
        graph_name = f"{section_list[section_choice][0]} Call Graph"
        for addr in range(start_addr,end_addr,bv.address_size):
            data_variable = bv.get_data_var_at(addr)
            if data_variable:
                current_graph_node = FlowGraphNode(graph_view)
                root_node = DumbGraphNode()
                if data_variable.name:
                    name = data_variable.name
                else:
                    name = hex(data_variable.address)
                root_node.text = name
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
                root_node.graph_view_node = current_graph_node
                # Add node
                dumb_graph_nodes.append(root_node)
                #graph_view.append(current_graph_node)

                marked_funcs = []
                for code_ref in data_variable.code_refs:
                    if code_ref.function.name in marked_funcs:
                        continue
                    new_node = DumbGraphNode()
                    new_node.parent_node = root_node
                    root_node.child_nodes.append(new_node)
                    new_node.text = code_ref.function.name
                    new_node.graph_view_parent = current_graph_node
                    
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
                    new_node.graph_view_node = xref_graph_node
                    dumb_graph_nodes.append(new_node)
                    make_simple_call_graph(new_node,code_ref.function,nodes)
        if type_choice == 0:
            connect_everything(graph_view)
        elif type_choice == 1:
            connect_graph_names_only(graph_view)

        graph_view.layout_and_wait()
        graph_view.show(graph_name)

