#!/usr/bin/env python3

from typing import List, Optional

from src.ida_compat import execute_on_main_thread

try:
    import ida_funcs
    import idautils
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


class IDAFunctionSignatureGenerator:
    """Best-effort IDA implementation of Sigga-style byte masking."""

    def generate(self, func_ea: Optional[int]) -> Optional[str]:
        if not _IN_IDA or func_ea is None:
            return None

        holder = {"signature": None}

        def _collect() -> None:
            func = ida_funcs.get_func(func_ea)
            if not func:
                return

            tokens: List[str] = []
            for item_ea in idautils.FuncItems(func.start_ea):
                if not idc.is_code(idc.get_full_flags(item_ea)):
                    continue
                size = int(idc.get_item_size(item_ea) or 0)
                if size <= 0:
                    continue
                data = idc.get_bytes(item_ea, size)
                if not data:
                    continue
                disasm = idc.generate_disasm_line(item_ea, 0) or ""
                tokens.extend(self._mask_instruction(disasm, data))
                if len(tokens) >= 64:
                    break

            trimmed = self._trim_trailing_wildcards(tokens)
            holder["signature"] = " ".join(trimmed) if trimmed else None

        execute_on_main_thread(_collect)
        return holder["signature"]

    def _mask_instruction(self, text: str, data: bytes) -> List[str]:
        tokens = [f"{byte:02X}" for byte in data]
        if not tokens:
            return tokens

        parts = text.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""
        operand_text = parts[1].lower() if len(parts) > 1 else ""

        if self._is_branch_like(mnemonic):
            for index in range(1, len(tokens)):
                tokens[index] = "?"
            return tokens

        if self._should_mask_operands(operand_text) and len(tokens) > 1:
            start = max(1, len(tokens) - min(4, len(tokens) - 1))
            for index in range(start, len(tokens)):
                tokens[index] = "?"

        return tokens

    @staticmethod
    def _is_branch_like(mnemonic: str) -> bool:
        return mnemonic.startswith("j") or mnemonic.startswith("call") or mnemonic.startswith("b")

    @staticmethod
    def _should_mask_operands(operand_text: str) -> bool:
        return any(marker in operand_text for marker in (
            "offset",
            "loc_",
            "sub_",
            "off_",
            "[",
            "0x",
            "cs:",
            "ds:",
            "extrn",
        ))

    @staticmethod
    def _trim_trailing_wildcards(tokens: List[str]) -> List[str]:
        trimmed = list(tokens)
        while trimmed and trimmed[-1] == "?":
            trimmed.pop()
        return trimmed
