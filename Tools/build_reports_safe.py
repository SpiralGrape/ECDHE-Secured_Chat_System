# -*- coding: utf-8 -*-
"""在报告文件被 WPS/Word 占用时，先把两份 docx 生成到临时目录，再尝试替换。

用法：python Tools\build_reports_safe.py
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import make_reports as m  # noqa: E402

TMP_OUT = os.path.join(os.environ.get("TEMP", "."), "reports_new")
NAMES = [
    "专业程序设计报告-成员A-密码协议方向.docx",
    "专业程序设计报告-成员B-网络与工程化方向.docx",
]


def main():
    os.makedirs(TMP_OUT, exist_ok=True)
    m.OUTDIR = TMP_OUT
    m.main()

    print("\n替换到 docs/ ...")
    failed = []
    for n in NAMES:
        src = os.path.join(TMP_OUT, n)
        dst = os.path.join(ROOT, "docs", n)
        try:
            shutil.copyfile(src, dst)
            print("  OK   ", n)
        except OSError as e:
            failed.append(n)
            print("  LOCKED", n, "->", e)

    if failed:
        print("\n以下文件被占用，未能覆盖（新版本已放在 %s）：" % TMP_OUT)
        for n in failed:
            print("  ", os.path.join(TMP_OUT, n))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
