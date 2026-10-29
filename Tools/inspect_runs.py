from docx import Document
from docx.shared import Pt

path = r"C:\Users\陈浩然\Desktop\一些文件\大四上实践周\专业程序设计报告模板.docx"
d = Document(path)

def dump(idx):
    p = d.paragraphs[idx]
    print(f"--- [{idx}] style={p.style.name} align={p.alignment} text={p.text.strip()[:40]!r}")
    pf = p.paragraph_format
    print("    first_line_indent", pf.first_line_indent, "space_before", pf.space_before,
          "space_after", pf.space_after, "line_spacing", pf.line_spacing)
    for r in p.runs[:3]:
        print("    run:", repr(r.text[:20]), "bold", r.bold, "size", r.font.size,
              "name", r.font.name, "eastasia", r._element.rPr.rFonts.get(
                  '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}eastAsia')
              if r._element.rPr is not None and r._element.rPr.rFonts is not None else None)

for i in [8, 9, 12, 21, 22, 23, 24, 27, 28, 30, 36, 39, 40, 122, 149, 150, 151, 162]:
    dump(i)

print("\n=== table styles ===")
print([s.name for s in d.styles if s.type == 3][:20])
print("\n=== doc default font ===")
st = d.styles['Normal']
print(st.font.name, st.font.size)
