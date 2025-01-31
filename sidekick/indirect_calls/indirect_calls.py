
from binaryninja import BinaryView, MediumLevelILOperation, MediumLevelILCall, MediumLevelILJump


def indexer(bv: BinaryView):
    for insn in current_mlil.instructions:
        if isinstance(insn, (MediumLevelILCall, MediumLevelILJump)):
            if (
                insn.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR and
                insn.dest.operation != MediumLevelILOperation.MLIL_IMPORT
            ):
                yield insn


with open_index(bv, f'Indirect Calls in {current_function.name}') as index:
    entries = list(indexer(bv))
    for i, entry in enumerate(entries):
        notify_progress(i, len(entries), 'Running Indirect Calls...')
        metadata = None
        if isinstance(entry, tuple):
            entry, metadata = entry
        index.add_entry(entry, metadata)
