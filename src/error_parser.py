import re
import os
from models import CompilerError

error_pattern=re.compile(
    r"^(?P<file>.+?):"
    r"(?P<line>\d+)"
    r"(?::(?P<col>\d+))?"
    r":\s*"
    r"(?P<type>error|warning|note):"
    r"\s*(?P<message>.*)$"
)

def get_source_context(path,line_no,context_lines=2):
    if not path:
        return None

    if not os.path.exists(path):
        return None

    try:
        with open(path,"r") as f:
            lines=f.readlines()
        start=max(0,line_no-1-context_lines)
        end=min(len(lines),line_no+context_lines)

        return{
            "start_line":start+1,
            "lines":lines[start:end]
        }

    except Exception:
        return None

def parse_errors(raw_output):
    errors=[]
    if not raw_output:
        return errors

    if isinstance(raw_output,list):
        for item in raw_output:
            error_obj=CompilerError(
                file=item.get("file"),
                line=item.get("line"),
                column=item.get("column"),
                error_type=item.get("type"),
                message=item.get("message"),
                raw=item.get("raw"),
                option=item.get("option"),
                notes=item.get("notes"),
                instantiation=item.get("instantiation", False),
                cascade=item.get("cascade", False),
                anchored_from=item.get("anchored_from"),
                suppressed=item.get("suppressed", 0),
            )
            if item.get("category"):
                error_obj.category=item.get("category")
                error_obj.confidence=item.get("confidence", 0.0)
            if item.get("detail"):
                error_obj.detail=item.get("detail")

            if error_obj.file and error_obj.line:
                if os.path.exists(error_obj.file):
                    error_obj.context=get_source_context(
                        error_obj.file,
                        error_obj.line
                    )

            errors.append(error_obj)
        return errors

    lines=raw_output.splitlines()
    i=0

    while i<len(lines):
        current=lines[i].strip()
        if "Undefined symbols for architecture" in current:
            block=[current]
            i+=1

            while i<len(lines):
                line=lines[i].strip()
                block.append(line)

                if "ld: symbol(s) not found for architecture" in line:
                    break
                i += 1

            message_text="\n".join(block)

            errors.append(
                CompilerError(
                    file=None,
                    line=None,
                    column=None,
                    error_type="linker",
                    message=message_text,
                    raw=message_text
                )
            )
            i += 1
            continue

        match=error_pattern.match(current)

        if match:
            groups=match.groupdict()
            error_obj=CompilerError(
                file=groups["file"],
                line=int(groups["line"]),
                column=int(groups["col"]) if groups.get("col") else None,
                error_type=groups["type"],
                message=groups["message"].strip(),
                raw=current
            )

            if error_obj.file and error_obj.line:
                if os.path.exists(error_obj.file):
                    error_obj.context=get_source_context(
                        error_obj.file,
                        error_obj.line
                    )
            errors.append(error_obj)
        i+=1

    return errors