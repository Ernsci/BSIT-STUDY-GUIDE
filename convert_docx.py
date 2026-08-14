import sys
from pathlib import Path

import win32com.client


def convert(path):
    src = Path(path).resolve()
    if not src.exists():
        print(f"Not found: {src}")
        return
    out = src.with_suffix(".pdf")
    word = win32com.client.Dispatch("Word.Application")
    word.Visible = False
    try:
        doc = word.Documents.Open(str(src))
        doc.SaveAs2(str(out), FileFormat=17)
        doc.Close()
        print(f"Converted: {out}")
    finally:
        word.Quit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_docx.py file.docx")
        sys.exit(1)
    convert(sys.argv[1])