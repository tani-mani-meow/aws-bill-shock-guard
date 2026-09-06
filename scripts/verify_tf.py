"""Static validator for Terraform files in the repository."""

import pathlib
import sys


def verify_file(f: pathlib.Path) -> bool:
    content = f.read_text(encoding="utf-8")
    stack = []
    in_str = False
    in_heredoc = False
    heredoc_marker = ""
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        # Handle heredoc
        if in_heredoc:
            if line.strip() == heredoc_marker:
                in_heredoc = False
            continue

        if "<<-EOT" in line:
            in_heredoc = True
            heredoc_marker = "EOT"
            continue
        elif "<<-EOF" in line:
            in_heredoc = True
            heredoc_marker = "EOF"
            continue

        # Strip line comments (# and //)
        stripped = ""
        in_line_str = False
        escape = False
        for ch in line:
            if ch == '"' and not escape:
                in_line_str = not in_line_str
            if not in_line_str and ch in ("#",):
                break
            stripped += ch
            escape = ch == "\\" and not escape

        escape = False
        for col_idx, ch in enumerate(stripped, start=1):
            if ch == '"' and not escape:
                in_str = not in_str
            elif not in_str:
                if ch in "{[(":
                    stack.append((ch, line_idx, col_idx))
                elif ch in "}])":
                    if not stack:
                        print(f"Error in {f}:{line_idx}:{col_idx} -> Unexpected closing {ch}")
                        return False
                    prev, p_line, p_col = stack.pop()
                    expected = {"{": "}", "[": "]", "(": ")"}[prev]
                    if ch != expected:
                        err_msg = (
                            f"Error in {f}:{line_idx}:{col_idx} -> Mismatched {ch}, "
                            f"expected {expected} (opened at line {p_line}:{p_col})"
                        )
                        print(err_msg)
                        return False
            escape = ch == "\\" and not escape

    if stack:
        print(f"Error in {f}: Unclosed brackets: {stack}")
        return False
    if in_str:
        print(f"Error in {f}: Unterminated string")
        return False

    return True


def main() -> None:
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    tf_files = list(repo_root.glob("terraform/**/*.tf"))
    print(f"Validating syntax on {len(tf_files)} Terraform files...")

    all_ok = True
    for f in sorted(tf_files):
        if not verify_file(f):
            all_ok = False
        else:
            print(f"  OK: {f.relative_to(repo_root)}")

    if not all_ok:
        print("Validation failed.")
        sys.exit(1)

    print("All Terraform files passed static syntax validation.")


if __name__ == "__main__":
    main()
