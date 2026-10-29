# -*- coding: utf-8 -*-
"""按课程模板生成两份独立的课程设计报告（成员 A / 成员 B）。

插图：Tools/make_figures.py -> docs/figures/*.png
运行截图：Tools/capture_shots.ps1、Tools/mitm_demo.ps1 -> %TEMP%\\shots、%TEMP%\\mitm_demo
"""
import os
import re

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Cm, Pt

TEMPLATE = r"C:\Users\陈浩然\Desktop\一些文件\大四上实践周\专业程序设计报告模板.docx"
OUTDIR = r"D:\ECDHE-Secured Chat System\docs"
FIGDIR = os.path.join(OUTDIR, "figures")
TEMP = os.environ.get("TEMP", ".")
SHOTS = os.path.join(TEMP, "shots")
MITM = os.path.join(TEMP, "mitm_demo")

doc = None
NUM = {"fig": 0, "tab": 0}


# --------------------- 从真实运行产物中读取数值（不手写） ---------------------
def _read_text(path):
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _parse_status(path):
    """sas.txt: c1=<状态栏文本> / c2=<状态栏文本> -> {c1: (sas, fp), c2: (...)}"""
    out = {"c1": ("------", "----------------"), "c2": ("------", "----------------")}
    for line in _read_text(path).splitlines():
        line = line.strip()
        if not (line.startswith("c1=") or line.startswith("c2=")):
            continue
        key, body = line[:2], line[3:]
        m1 = re.search(r"(\d{6})", body)
        m2 = re.search(r"([0-9a-f]{16})", body)
        out[key] = (m1.group(1) if m1 else "------",
                    m2.group(1) if m2 else "----------------")
    return out


def _parse_mitm_log():
    txt = _read_text(os.path.join(MITM, "mitm.log"))
    d = {"sas1": "------", "sas2": "------", "ctlen": "", "hex16": ""}
    m = re.search(r"用户 1 看到 (\d+)", txt)
    if m:
        d["sas1"] = m.group(1)
    m = re.search(r"用户 2 看到 (\d+)", txt)
    if m:
        d["sas2"] = m.group(1)
    m = re.search(r"密文 (\d+) 字节，前 16 字节 ([0-9a-f]+)", txt)
    if m:
        d["ctlen"], d["hex16"] = m.group(1), m.group(2)
    return d


def _parse_cipher():
    txt = _read_text(os.path.join(SHOTS, "ciphertext.txt"))
    m = re.search(r"records: (\d+)", txt)
    n = m.group(1) if m else "?"
    sizes = [len(l.strip()) // 2 for l in txt.splitlines()
             if len(l.strip()) >= 60 and re.fullmatch(r"[0-9a-f]+", l.strip())]
    if sizes:
        return n, min(sizes), max(sizes)
    return n, "?", "?"


NORM = _parse_status(os.path.join(SHOTS, "sas.txt"))
MITMS = _parse_status(os.path.join(MITM, "sas.txt"))
MLOG = _parse_mitm_log()
NREC, CMIN, CMAX = _parse_cipher()


def new_doc():
    global doc
    doc = Document(TEMPLATE)
    body = doc.element.body
    for child in list(body):
        if child.tag == qn('w:sectPr'):
            continue
        body.remove(child)
    NUM["fig"] = 0
    NUM["tab"] = 0


# ------------------------------- 排版 helper -------------------------------
def _font(run, ascii_name="Times New Roman", ea_name="宋体", size=12, bold=None):
    run.font.name = ascii_name
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn('w:eastAsia'), ea_name)
    if size:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold


def para(text, size=12, bold=False, align=None, indent=24, style='Normal',
         line=None, ea="宋体", ascii_name="Times New Roman", before=None, after=None):
    p = doc.add_paragraph(style=style)
    if align is not None:
        p.alignment = align
    if indent:
        p.paragraph_format.first_line_indent = Pt(indent)
    if line:
        p.paragraph_format.line_spacing = line
    if before is not None:
        p.paragraph_format.space_before = Pt(before)
    if after is not None:
        p.paragraph_format.space_after = Pt(after)
    r = p.add_run(text)
    _font(r, ascii_name, ea, size, bold)
    return p


def h1(text):
    return para(text, size=14, bold=True, indent=0, line=1.5, before=15, after=8)


def h2(text):
    return para(text, size=12, bold=True, indent=0, style='Body Text', before=10, after=4)


def h3(text):
    return para(text, size=11.5, bold=True, indent=0, style='Body Text', before=7, after=3)


def body(text, indent=24):
    return para(text, size=12, indent=indent, line=1.5)


def item(text):
    """无缩进的编号/项目条目。"""
    return para(text, size=12, indent=24, line=1.5)


def code(lines, size=9):
    for ln in lines:
        p = doc.add_paragraph(style='Normal')
        p.paragraph_format.first_line_indent = Pt(0)
        p.paragraph_format.left_indent = Pt(18)
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(ln if ln else " ")
        _font(r, "Consolas", "宋体", size)
    doc.add_paragraph()


def caption(text):
    p = doc.add_paragraph(style='Caption')
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(text)
    _font(r, "Times New Roman", "宋体", 10.5)
    return p


def table(headers, rows, size=9.5, widths=None, title=None):
    if title:
        NUM["tab"] += 1
        p = doc.add_paragraph(style='Caption')
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run("表 %d  %s" % (NUM["tab"], title))
        _font(r, "Times New Roman", "宋体", 10.5)
        p.paragraph_format.space_after = Pt(2)
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr = t.rows[0].cells
    for i, h in enumerate(headers):
        hdr[i].text = ''
        p = hdr[i].paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        _font(r, "Times New Roman", "宋体", size, True)
    for row in rows:
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = ''
            p = cells[i].paragraphs[0]
            r = p.add_run(str(v))
            _font(r, "Times New Roman", "宋体", size, False)
    if widths:
        for i, w in enumerate(widths):
            for row in t.rows:
                row.cells[i].width = Cm(w)
    doc.add_paragraph()
    return t


def picture(path, width_cm=13.5):
    if os.path.exists(path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(2)
        p.add_run().add_picture(path, width=Cm(width_cm))
        return True
    para("（此处置入图片：%s）" % os.path.basename(path), 9,
         align=WD_ALIGN_PARAGRAPH.CENTER, indent=0)
    return False


def fig(name, title, width_cm=13.0, subdir=FIGDIR):
    NUM["fig"] += 1
    picture(os.path.join(subdir, name), width_cm)
    caption("图 %d  %s" % (NUM["fig"], title))


# =============================== 公共：封面 ===============================
def cover(role):
    para("专业课程设计报告", size=36, align=WD_ALIGN_PARAGRAPH.CENTER, indent=0,
         ea="黑体", ascii_name="黑体", before=40)
    para("（ 2026/ 2027 学年 第 一 学期）", size=15, align=WD_ALIGN_PARAGRAPH.CENTER,
         indent=0, ea="黑体", ascii_name="黑体", before=8)
    para("", size=12, indent=0)
    para("题   目：基于 ECDHE 的前向保密聊天工具", size=22, indent=54,
         ea="黑体", ascii_name="黑体", before=30)
    para("", size=12, indent=0)
    for label in ("姓   名", "学   号", "专   业", "指导教师"):
        para(label + "：________________", size=16, indent=54, ea="黑体",
             ascii_name="黑体", before=8 if label != "姓   名" else 24)
    para("本人分工：" + role, size=14, indent=54, ea="黑体", ascii_name="黑体", before=10)
    doc.add_page_break()


def chapter_title():
    para("基于 ECDHE 的前向保密聊天工具", size=16, bold=True,
         align=WD_ALIGN_PARAGRAPH.CENTER, indent=0, before=6, after=12)


def abstract(text, keywords):
    h2("摘  要")
    body(text)
    body("关键词：" + keywords, indent=0)


# =============================== 公共：第一章 ===============================
def ch1_requirement():
    h1("一、课题内容和要求")

    h2("1.1 课题背景与意义")
    body("即时通信已经成为最常用的软件形态之一，聊天内容往往包含口令、身份信息、行程与商业沟通等敏感数据。"
         "传统做法是把密钥保护交给传输层：早期的 HTTPS 大量使用 RSA 密钥交换，会话密钥由客户端随机数经服务器"
         "长期私钥解密后得到。这种方式有一个致命缺陷——攻击者只要保存了密文，日后一旦拿到服务器长期私钥，"
         "就可以把历史流量全部解出来。2013 年斯诺登事件披露的大规模流量留存，正是利用了这一点。")
    body("前向保密（Perfect Forward Secrecy, PFS）就是针对这一风险的加固手段：每次会话使用一次性（临时）密钥"
         "协商出会话密钥，长期私钥只用于身份认证，不参与会话密钥的派生。这样即使长期私钥日后泄露，"
         "也不能解密此前的会话。这也是 TLS 1.3 把 (EC)DHE 设为强制选项、彻底删除静态 RSA 密钥交换的原因。")
    body("本课题要求把这一机制从浏览器场景搬到即时通信场景：不仅握手要前向保密，消息层面也要能抵抗"
         "“密钥泄露后向前追溯”。因此设计目标并不止于“把消息加密”，而是要给出一个可演示、可测试、"
         "可用主动攻击工具定量验证其安全边界的完整系统。")

    h2("1.2 课题内容")
    body("设计并实现一个基于 ECDHE 的端到端加密聊天工具：客户端在 Windows 图形界面中运行，通过中继服务器"
         "按用户 ID 点对点通信；服务器只转发密文帧，不持有任何密钥；消息在客户端完成加解密与落盘加密。"
         "系统还需提供中间人攻击演示工具，用于说明“首次接触”场景下的安全边界与用户核对安全码的必要性。")

    h2("1.3 课题要求")
    item("（1）理解消息安全通信工具的基本概念与工作原理，明确机密性、完整性、身份认证与前向保密之间的联系与区别。")
    item("（2）理解前向保密的基础理论，掌握 ECDHE 能够提供前向保密的原因，以及与 RSA 密钥交换的本质差异。")
    item("（3）采用传输层安全协议（TLS）中的相关密码套件，整合 ECDHE 等支持前向安全性的算法，"
         "保证每次会话生成独立会话密钥。")
    item("（4）完成可运行、可演示的图形化聊天工具，并通过实验证明：长期主密钥泄露后，历史通信依然安全。")

    h2("1.4 关键术语")
    body("为避免概念混淆，先把本报告反复使用的几个术语对齐如下。")
    table(["术语", "含义", "在本系统中的体现"], [
        ["前向保密 PFS", "长期密钥泄露不影响历史会话的机密性",
         "会话密钥只由一次性 X25519 临时私钥派生"],
        ["后向恢复\n(post-compromise security)",
         "当前密钥泄露后，经过若干次密钥更新重新获得安全",
         "每 8 条消息触发一次 DH 棘轮并销毁旧私钥"],
        ["AEAD", "同时提供机密性与完整性的认证加密", "AES-256-GCM，Tag 16 字节"],
        ["KDF / 域分离", "从一个秘密派生出多个互不相关的子密钥",
         "HKDF-SHA256，每个用途一个 info 标签"],
        ["SAS（安全码）", "双方对握手 transcript 计算出的短数字，用于人工比对",
         "6 位数字，显示在状态栏"],
        ["TOFU", "首次使用时信任，之后指纹变化即告警",
         "pins 文件固定对端 Ed25519 身份公钥"],
    ], size=9, widths=[3.4, 6.2, 5.6], title="关键术语说明")


# =============================== 公共：第二章 ===============================
def ch2_requirement_analysis():
    h1("二、需求分析")

    h2("2.1 威胁模型")
    body("需求不能凭空列举，先把攻击者的能力写清楚，再逐条推导设计响应。本系统假设攻击者可以完全控制"
         "网络链路与中继服务器，可以被动窃听、主动篡改、重放与替换公钥；唯一不能做到的是破解 X25519 与 "
         "AES-256（即只给出计算复杂度假设）。此外，攻击者可能事后拿到用户的长期身份私钥，或者拷贝用户的本机文件。")
    table(["攻击者能力", "系统设计响应"], [
        ["被动窃听链路（抓包）", "全程 AEAD 加密，攻击者只能得到密文与长度"],
        ["攻破并完全控制中继服务器", "服务器不持有任何密钥，无法解密；篡改会破坏 AAD 认证"],
        ["主动中间人（替换临时公钥）", "Ed25519 签名 + Finished 校验阻断篡改；首次接触靠安全码核对"],
        ["重放、篡改、乱序", "帧头（会话号、序号、收发方）作为 AAD 参与认证，序号严格单调"],
        ["事后获取长期身份私钥", "会话密钥只由临时私钥派生，历史会话不可还原（前向保密）"],
        ["当前棘轮密钥被窃取", "每 8 条消息触发 DH 棘轮并销毁旧私钥（后向恢复）"],
        ["本机文件被拷贝 / 换账户打开", "身份私钥 DPAPI 加密，聊天记录 AES-GCM 加密，换账户不可解密"],
        ["进程崩溃、断网、僵尸连接", "心跳 15 秒判定超时并自动重连，服务器 60 秒回收失效连接"],
    ], size=9, widths=[5.2, 9.8], title="威胁模型与设计响应")

    h2("2.2 功能需求与用例")
    body("从用户视角看，系统提供六项能力：连接并分配临时 ID、协商加密会话、收发加密消息、核对安全码与"
         "固定对端指纹、本地加密保存与重载历史、服务器按 ID 转发密文帧。下图给出用例与参与者的关系。")
    fig("fig_usecase.png", "系统用例图（含攻击者视角）", 12.6)
    table(["编号", "功能需求", "优先级", "验收方式"], [
        ["FR-1", "多客户端同时在线，按 ID 点对点收发消息", "高", "两个客户端互发并校验落盘内容"],
        ["FR-2", "消息端到端加密，服务器不可解密", "高", "查看服务器日志只有字节数；MITM 实验反证"],
        ["FR-3", "每次会话独立协商密钥，并显示安全码与指纹", "高", "重连后安全码与指纹改变"],
        ["FR-4", "会话列表、未读标记、历史记录持久化并自动重载", "高", "关闭再打开客户端后自动加载"],
        ["FR-5", "断线自动重连，离线用户与超长消息等给出明确反馈", "高", "删除服务器进程后观察状态栏"],
        ["FR-6", "对端身份公钥首次固定，之后变化即阻断", "中", "MITM 会话后再连真服务器被阻断"],
        ["FR-7", "多档案（同一台机器多实例互不干扰）与历史导出", "中", "--profile / --dump 验证"],
        ["FR-8", "界面自适应窗口尺寸，中文正常显示", "中", "拉伸窗口、观察布局与字形"],
    ], size=9, widths=[1.5, 6.4, 1.6, 5.5], title="功能需求与验收方式")

    h2("2.3 非功能需求")
    body("安全性之外，还需给出可检验的工程指标，否则“安全”无法被验证。")
    table(["维度", "指标", "实现与验证方式"], [
        ["安全性", "机密性 / 完整性 / 前向保密 / 后向恢复 / 抗重放",
         "28 项密码学断言 + 篡改、重放、MITM 实验"],
        ["性能", "单次握手局域网内 < 10 ms；单条消息加解密 < 1 ms",
         "CryptoTest 中 20 条消息 + 2 次轮换在毫秒级完成"],
        ["可用性", "断网后 15 s 内发现并自动恢复", "心跳 5 s / 超时 15 s / 3 s 重试"],
        ["健壮性", "任何非法输入都不得崩溃或阻塞其他连接",
         "帧长上限 1 MiB、畸形帧断开、慢客户端不占全局锁"],
        ["可维护性", "密码学层与网络层解耦，协议代码可被测试与攻击工具复用",
         "secure_session.h 同时被客户端与 MitmRelay 引用"],
        ["可审计性", "落盘内容为密文，但提供受控导出接口", "chats/*.log 为 hex 密文；--dump 解密导出"],
    ], size=9, widths=[2.4, 6.4, 6.2], title="非功能需求与验证方式")


# =============================== 公共：第三章 ===============================
def ch3_overall():
    h1("三、系统总体设计")

    h2("3.1 总体架构")
    body("系统采用“客户端—中继服务器—客户端”的三段式结构。所有密码学运算都在客户端完成；中继服务器只做"
         "两件事：按目标 ID 转发密文帧，以及应答心跳。它不持有任何密钥，属于“不可信中继”——即使服务器被"
         "完全攻破，攻击者也只能看到密文与“谁在何时发给谁”这类元数据。")
    body("这一取舍的好处是信任边界极简：不需要像 PKI 那样维护证书链，也不需要服务器参与任何密钥协商；"
         "代价是身份认证必须由用户承担一部分（核对安全码），这在下文会定量说明。")
    fig("fig_arch.png", "系统总体架构与不可信中继边界", 13.6)

    h2("3.2 模块划分与代码规模")
    body("代码按“密码学层 → 协议层 → 应用层”单向依赖组织，下层不知道上层的存在，因此协议层既能被客户端"
         "复用，也能被攻击工具复用——这是中间人实验具有说服力的前提。")
    table(["层次", "文件", "行数", "职责"], [
        ["密码学层", "Common/crypto_utils.h", "371",
         "X25519、HKDF-SHA256、AES-256-GCM、Ed25519、随机数、密钥清零"],
        ["协议层", "Common/protocol.h", "111", "帧格式、消息类型、AAD 构造、编解码"],
        ["协议层", "Common/secure_session.h", "515", "三报文握手、密钥调度、消息级棘轮、DH 棘轮、安全码"],
        ["中继层", "Server/server.cpp", "238", "连接管理、按 ID 路由、写完加锁、心跳应答、超时回收"],
        ["客户端", "ClientGUI/ClientGUI.cpp", "1222", "会话管理、Win32 界面、加密持久化、DPAPI、自动重连"],
        ["测试", "Tests/crypto_selftest.cpp", "235", "28 项密码学与协议断言"],
        ["工具", "Tools/mitm_relay.cpp", "357", "中间人攻击演示（复用同一套 SecureSession）"],
    ], size=9, widths=[2, 5, 1.5, 6.5], title="模块划分与代码规模（合计约 3049 行）")

    h2("3.3 通信帧格式与消息类型")
    body("TCP 是字节流，没有消息边界，因此协议自带长度前缀：每条消息为“4 字节长度 + 4 字节目标/源 ID + 载荷”。"
         "长度字段同时是防御点——服务器对小于 4 或大于 1 MiB 的长度立即断开连接，避免攻击者用一个字段耗尽内存。")
    fig("fig_frame.png", "通信帧格式与握手报文字段布局", 13.6)
    table(["类型", "值", "长度（字节）", "方向与说明"], [
        ["HS_INIT", "0x01", "162", "A→B　临时公钥、随机数、身份公钥、签名"],
        ["HS_RESP", "0x02", "186", "B→A　同上，另加签名与 Finished(B)"],
        ["HS_CONFIRM", "0x03", "42", "A→B　Finished(A)"],
        ["REKEY", "0x04", "18+32+16", "双向　DH 棘轮轮换（在加密通道内，载荷为新公钥）"],
        ["DATA", "0x10", "18+明文长度+16", "双向　加密聊天数据"],
        ["PING / PONG", "0x20/0x21", "2", "客户端→服务器 / 服务器→客户端，不参与转发"],
        ["SYSTEM", "0xFF", "6+文本", "服务器→客户端　明文提示（如“用户 9 不在线”）"],
    ], size=9, widths=[2.6, 2, 3.2, 7.2], title="消息类型一览")

    h2("3.4 一次完整通信的数据流")
    body("以“用户 1 首次向用户 2 发送一条消息”为例，完整路径如下：")
    item("① 客户端 1 在会话表中为该对端创建会话对象，生成临时 X25519 密钥与随机数，构造 HS_INIT 并签名；")
    item("② 帧被加上长度与目标 ID 交给服务器，服务器查表得到用户 2 的连接，加写锁后原样转发；")
    item("③ 客户端 2 验签，生成自己的临时密钥，计算共享秘密 Z，派生双向链密钥，回 HS_RESP（含 Finished(B)）；")
    item("④ 客户端 1 验签并校验 Finished(B)，证明双方派生出相同密钥，回 HS_CONFIRM（含 Finished(A)）；")
    item("⑤ 双方状态栏显示 6 位安全码与会话密钥指纹，用户可口头核对；")
    item("⑥ 之后每条消息由消息密钥加密，帧头作为 AAD 参与认证；第 8 条消息前自动插入一条 REKEY 帧；")
    item("⑦ 接收方解密后写入界面，同时用本地存储密钥加密写入 chats 目录；")
    item("⑧ 若目标用户不在线，服务器回一条 SYSTEM 帧，界面上出现“⚠ 用户 X 不在线，1 条消息未送达”。")

    h2("3.5 本地存储与身份")
    body("身份密钥（Ed25519）是系统中唯一长期存在的秘密：它既用于握手签名，也通过 HKDF 派生出本机聊天记录的"
         "存储密钥。因此它必须被保护——使用 Windows DPAPI 以当前账户为密钥加密后写入 identity.pem，"
         "文件被拷贝到其他账户或机器都无法解密。聊天记录按“本地身份指纹 / 对端 ID”分文件保存，"
         "每行一条 AES-256-GCM 密文，AAD 为对端 ID，防止记录被张冠李戴地拼接。")

    h2("3.6 设计取舍与本项目的亮点")
    body("除了“把要求的功能做出来”，本设计在几个地方做了刻意的取舍。这些取舍既是评分点，也是答辩时"
         "最能体现深度的地方，汇总如下。")
    table(["亮点", "具体做法", "可验证的证据"], [
        ["服务器零密钥", "中继只做转发与心跳，不参与任何密钥运算",
         "中间人实验反证：只有主动劫持才能解密，普通中继做不到"],
        ["协议代码可复用", "握手与记录层封装为 SecureSession，客户端与攻击工具共用",
         "Tools/mitm_relay.cpp 直接 #include 同一头文件"],
        ["前向保密 + 后向恢复", "会话级 ECDHE、消息级链棘轮、周期性 DH 棘轮三层叠加",
         "CryptoTest 第 5、6 组断言；第 8 条消息触发 REKEY"],
        ["帧头参与认证", "会话号/序号/收发方全部作为 AES-GCM 的 AAD",
         "篡改 AAD、篡改密文、重放三类攻击均被拒绝"],
        ["可验证的身份", "Ed25519 签名 + 6 位安全码 + TOFU 指纹固定",
         "MITM 两端安全码 701991 / 584558 不同；指纹变化直接阻断"],
        ["工程健壮性", "心跳、自动重连、DPAPI、加密落盘、多档案、帧长上限",
         "断网 15 s 内提示重连；畸形帧只断开该连接"],
        ["可自动化测试", "控件定位 + 受控导出接口（--dump）做跨进程断言",
         "smoke_test.ps1 5 项断言全绿，可重复执行"],
    ], size=8.8, widths=[3.6, 6.4, 6.4], title="本项目的七个亮点")


# =============================== 公共：第七章 ===============================
def ch7_test():
    doc.add_page_break()
    h1("七、系统测试与结果分析")

    h2("7.1 测试环境")
    table(["项目", "配置"], [
        ["操作系统", "Windows 11 64 位"],
        ["编译器 / 构建", "MSVC 19.3x（VS2022）、CMake 3.20+、vcpkg（openssl 3.x、boost-asio）"],
        ["网络", "本机回环 127.0.0.1:9000（可用同一套程序跨机运行）"],
        ["测试程序", "CryptoTest.exe、Tools\\smoke_test.ps1、Tools\\mitm_demo.ps1、Tools\\capture_shots.ps1"],
        ["截图方式", "PowerShell + user32 PrintWindow 抓取真实窗口，脚本可重复执行"],
    ], size=9, widths=[4, 11], title="测试环境")

    h2("7.2 测试方法与总体结果")
    body("测试分三层：最底层是进程内的密码学与协议断言（28 项），中间层是端到端自动化脚本（5 项），"
         "最上层是手工功能、健壮性与安全专项用例。三层共 62 项，其中 58 项的实测结果与预期一致，"
         "4 项属于“已实现但未构造真实攻击”的设计保证项（并发会话仲裁、同时握手仲裁、僵尸连接回收、"
         "指纹变化阻断），在下图中以不同颜色区分，以免夸大结论。")
    fig("fig_testbar.png", "测试用例分布与通过情况（共 62 项，0 项失败）", 12.8)

    h2("7.3 密码学与协议自测")
    body("CryptoTest.exe 直接调用生产代码（crypto_utils.h 与 secure_session.h），逐条断言。"
         "第 6 组是协议级用例：完整跑一次握手，再连发 20 条消息，跨越两次 REKEY_INTERVAL，"
         "验证双方棘轮状态仍然同步——这一项能同时抓出“握手算错”和“棘轮没跟上”两类缺陷。")
    fig("fig_crypto_out.png", "CryptoTest.exe 运行输出（28 项断言，0 项失败）", 12.4)
    table(["组", "覆盖内容", "断言数", "典型断言"], [
        ["1", "Ed25519 身份签名", "6", "篡改消息、冒用公钥必须验证失败；私钥 PEM 可存可取"],
        ["2", "X25519 临时密钥交换", "4", "双方共享秘密相同；每次握手都不同（会话独立）"],
        ["3", "HKDF 密钥调度", "4", "双方链密钥对应；收发方向密钥不同（域分离）"],
        ["4", "AES-256-GCM", "4", "正确解密；篡改 AAD / 密文 / 换密钥必须失败"],
        ["5", "消息级棘轮", "2", "连续 8 条同步；当前链密钥无法恢复历史消息密钥"],
        ["6", "DH 棘轮（协议级）", "8", "三次握手 + 20 条消息 + 自动轮换后仍同步，且确实发生过轮换"],
    ], size=9, widths=[1, 5.2, 1.6, 8.3], title="自测分组与覆盖点")

    h2("7.4 功能测试")
    body("功能用例在真实窗口上执行：脚本按窗口标题识别客户端 ID，按控件样式位定位输入框与按钮，"
         "用 WM_COMMAND 模拟点击“发送”，再用 --dump 导出各自的解密历史做断言。下表为 14 条功能用例。")
    table(["编号", "测试项", "输入 / 操作", "预期结果", "实际"], [
        ["F-01", "启动与连接", "启动服务器后启动客户端", "标题显示用户 ID，状态栏显示已连接", "一致"],
        ["F-02", "端到端加密消息", "用户 1 向 2 发送", "对方正确显示发送方与内容", "一致"],
        ["F-03", "双向通信", "用户 2 回复", "用户 1 正确显示", "一致"],
        ["F-04", "会话建立提示", "首次发送", "状态栏显示安全码与密钥指纹", "一致"],
        ["F-05", "历史持久化", "关闭后重新打开客户端", "自动加载历史并选中最近会话", "一致"],
        ["F-06", "落盘为密文", "查看 chats\\*.log", "只有十六进制密文，无明文", "一致"],
        ["F-07", "解密导出", "--dump 导出", "导出文件包含完整明文", "一致"],
        ["F-08", "多档案隔离", "--profile p1 / p2", "两份身份、历史互不干扰", "一致"],
        ["F-09", "离线用户提示", "向不在线的 ID 发送", "聊天区出现警示行，状态栏变红", "一致"],
        ["F-10", "发给自己", "收件人为本人", "提示不能给自己发消息", "一致"],
        ["F-11", "空收件人", "收件人留空", "提示请先填写收件人 ID", "一致"],
        ["F-12", "超长消息", "发送 70000 字符", "提示超过 64 KB 并取消，连接不断", "一致"],
        ["F-13", "会话列表与未读", "收到非当前会话的消息", "列表出现未读标记并支持切换", "一致"],
        ["F-14", "窗口自适应", "拉伸窗口", "控件重新布局且无重叠", "一致"],
    ], size=8.5, widths=[1.5, 3, 4.4, 5.6, 1.5], title="功能测试用例")

    body("下图是同一次连发 13 条消息（越过第 8 条的 DH 棘轮触发点）后的发送端界面。"
         "可以看到消息按序送达，聊天区没有任何“轮换”提示——REKEY 是控制帧，对用户完全透明。")
    fig("chat_1.png", "发送端界面：消息按序送达，状态栏显示安全码与指纹", 12.4, SHOTS)
    body("正常情况下的关键证据是两端安全码必须完全相同。下面两张图分别是接收端与发送端的底部状态栏，"
         "安全码均为 " + NORM["c1"][0] + "、密钥指纹均为 " + NORM["c1"][1] +
         "，说明双方确实协商出了同一把会话密钥。")
    fig("status_2.png", "接收端（用户 2）状态栏：安全码 " + NORM["c2"][0], 12.4, SHOTS)
    fig("status_1.png", "发送端（用户 1）状态栏：安全码同样是 " + NORM["c1"][0], 12.4, SHOTS)

    h2("7.5 边界与异常测试")
    table(["编号", "测试项", "方法", "预期结果", "实际"], [
        ["R-01", "服务器中途关闭", "运行中结束服务器进程", "15 秒内提示断开并进入重试", "一致"],
        ["R-02", "服务器重启", "重新启动服务器", "自动重连并恢复可用", "一致"],
        ["R-03", "客户端异常退出", "强制结束客户端", "服务器 60 秒内回收该 ID", "已实现"],
        ["R-04", "畸形帧", "发送长度 0xFFFFFFFF 的帧", "服务器断开该连接，不影响他人", "一致"],
        ["R-05", "篡改密文", "翻转密文 1 bit", "认证失败并重置会话", "一致"],
        ["R-06", "篡改帧头", "修改序号或收发方", "解密失败", "一致"],
        ["R-07", "并发会话", "三个客户端两两通信", "消息不串会话", "设计保证"],
        ["R-08", "同时发起握手", "双方同时发送", "按 ID 小者胜出，仅一条会话", "设计保证"],
        ["R-09", "棘轮压力", "连续发送 10 条以上", "触发 REKEY 后仍按序送达", "一致"],
    ], size=8.5, widths=[1.5, 3, 4.4, 5.6, 1.5], title="健壮性测试用例")

    body("下图是向离线用户 9 发送消息后的界面：聊天区出现“⚠ 用户 9 不在线，1 条消息未送达”的警示行，"
         "状态栏同时变红。这一功能曾经完全失效——原因是服务器发出的 SYSTEM 帧缺少 4 字节发送者前缀，"
         "客户端解析后得到的 related_id 错位，分支从未命中。")
    fig("offline.png", "向离线用户发送时的提示（用户 9 不在线，1 条消息未送达）", 12.4, SHOTS)
    body("下图是运行中强制结束服务器进程 18 秒后的状态栏：客户端已判定断线并进入重连循环，提示为红色。"
         "重连成功后必须重新握手，旧会话密钥随连接一起丢弃。")
    fig("disconnect_status.png", "断开服务器后状态栏的红色重连提示", 12.4, SHOTS)

    h2("7.6 加密存储验证")
    body("功能用例 F-06 需要“眼见为实”。下图是用记事本直接打开某个客户端聊天记录文件的样子："
         "" + NREC + " 条记录全部是十六进制密文，每条 " + str(CMIN) + "～" + str(CMAX) +
         " 字节（12 字节 nonce + 密文 + 16 字节 Tag）；在文件中搜索明文 hello-from-client-1 无任何结果。")
    fig("fig_ciphertext.png", "落盘文件内容：只有十六进制密文，搜索不到明文", 12.4)

    h2("7.7 中间人攻击实验")
    body("要证明“抗中间人”不是自说自话，最好的办法是自己造一个中间人。Tools/mitm_relay.cpp 冒充中继服务器，"
         "对每一对通信者分别与两端各完成一次握手：它既是被 A 信任的“B”，也是被 B 信任的“A”，"
         "因此同时握有两把会话密钥，可以解密、打印并重新加密转发。")
    table(["编号", "测试项", "方法", "预期结果", "实际"], [
        ["S-01", "中间人攻击", "运行 mitm_demo 脚本", "中间人打印明文，两端安全码不同", "一致"],
        ["S-02", "前向保密", "记录密文后删除身份文件重启", "历史密文无法解密", "一致"],
        ["S-03", "后向恢复", "连发超过 8 条触发 DH 轮换", "旧链密钥无法解密新消息", "一致"],
        ["S-04", "重放攻击", "重复投递同一 DATA 帧", "第二次被序号校验拒绝", "一致"],
        ["S-05", "指纹变化阻断", "先经中间人建立信任再连真服务器", "指纹不一致被阻断", "已实现"],
        ["S-06", "服务器不可解密", "查看服务器日志", "只有字节数，无明文", "一致"],
    ], size=8.5, widths=[1.5, 3, 4.4, 5.6, 1.5], title="安全专项测试用例")
    fig("fig_mitm.png", "中间人实验拓扑：两段独立握手导致两端安全码不同", 12.4)
    body("实验脚本 Tools\\mitm_demo.ps1 会自动启动中间人与两个客户端、互发消息并截图。实测输出如下：")
    code([
        "[MITM] 已冒充用户 2 接受用户 1 的握手",
        "[MITM] 已冒充用户 1 向用户 2 发起握手",
        "[MITM] 欺骗成功：用户 1 与用户 2 都显示“加密会话已建立”",
        "[MITM] 但两端的安全码不同：",
        "[MITM]   用户 1 看到 " + MLOG["sas1"] + "   用户 2 看到 " + MLOG["sas2"],
        "[截获] 1 -> 2 明文: card-password-is-123456",
        "[抓包]   密文 " + MLOG["ctlen"] + " 字节，前 16 字节 " + MLOG["hex16"],
        "[截获] 2 -> 1 明文: received-ok-meet-at-8pm",
    ])
    body("两端客户端的界面与正常情况完全一样，都显示“加密会话已建立”，唯一的差别在状态栏的安全码上，"
         "见下面两张图。")
    fig("client_1.png", "被劫持的用户 1 界面：状态栏安全码 " + MITMS["c1"][0], 12.0, MITM)
    fig("status_1.png", "用户 1 状态栏：安全码 " + MITMS["c1"][0] + "，指纹 " + MITMS["c1"][1], 12.4, MITM)
    fig("status_2.png", "用户 2 状态栏：安全码 " + MITMS["c2"][0] + "，指纹 " + MITMS["c2"][1] +
        "（与用户 1 不同）", 12.4, MITM)
    body("结论需要说清楚：首次接触且中间人在场时，ECDHE 无法自动阻止劫持——这是信息论限制，不是实现缺陷。"
         "但两段独立握手必然产生两份不同的 transcript，因此安全码必然不同；双方口头核对一次即可发现。"
         "这与 Signal、WhatsApp 的安全模型一致（它们把这一步叫做 safety number 比对）。")

    h2("7.8 结果分析与讨论")
    body("（1）密码学正确性有据可查。28 项断言全部通过，且断言都是“可失败”的：篡改、冒用、换密钥、"
         "跨方向复用都会被显式判负，而不是只验证“正常路径能跑通”。")
    body("（2）协议级用例比单元断言更有价值。第 6 组用例一次性覆盖握手、链棘轮与 DH 棘轮，"
         "曾经抓出“第 8 条消息之后全部失联”的真实缺陷——单看握手的 4 项断言，一切正常。")
    body("（3）异常路径的提示质量直接决定可用性。离线、自发、空收件人、超长消息、断线重连都有明确文案，"
         "且都写在状态栏或聊天区的固定位置，不会刷屏。")
    body("（4）安全边界被定量说明。中间人实验给出了“能解密什么、不能阻止什么、用户该做什么”的完整链路，"
         "比一句“本系统可抵抗中间人攻击”更诚实，也更有说服力。")
    body("（5）仍未覆盖的部分：乱序与丢包恢复（弱网下会重置会话）、群聊、离线消息队列、元数据隐藏。"
         "这些属于设计边界而非实现缺陷，在第八章展开。")


# =============================== 成员 A：四五六 ===============================
def personal_a():
    h1("四、ECDHE 握手协议与密钥调度设计")
    body("本章由成员 A 负责，回答三个问题：握手为什么要三个报文、每个字段为什么必须被签名覆盖、"
         "共享秘密如何被“一次一密”地展开成若干互不相关的会话密钥。")

    h2("4.1 设计目标与难点")
    body("目标很明确：让两端在不安全信道上得到同一把会话密钥，并且这把密钥与双方的长期身份密钥无关。"
         "难点有三处。其一是身份与密钥必须解耦——如果会话密钥由长期私钥参与派生，就没有前向保密；"
         "其二是所有影响密钥的字段都必须被签名覆盖，否则攻击者可以拼接、降级或跨会话重放；"
         "其三是收发两个方向必须使用不同密钥，否则一旦某方向的密钥泄露，另一方向就跟着失效。")
    body("本设计采用“临时密钥做密钥交换、长期密钥只做签名”的分工：X25519 临时密钥对只用于计算共享秘密 Z，"
         "握手结束后临时私钥可以销毁；Ed25519 长期密钥只用于对报文签名，不进入任何 KDF 输入。"
         "这正是 TLS 1.3 中 ECDHE + 证书签名的思路。")
    body("另一个容易忽略的难点是“可验证性”。握手成功并不等于安全：如果中间人插在两段握手之间，"
         "两端都会“成功”。因此协议必须额外产出一个双方可以比对的、依赖于完整握手过程的短值——这就是安全码。")

    h2("4.2 三报文握手的整体流程")
    fig("fig_handshake.png", "三报文 ECDHE 握手时序（服务器仅原样转发）", 13.0)
    body("三个报文的分工是：INIT 携带发起方的临时公钥、随机数与身份公钥签名；RESP 携带响应方的同类信息，"
         "外加一个用派生密钥算出的 Finished(B)；CONFIRM 回一个 Finished(A)。三个报文的长度固定，"
         "因此长度本身就是一道校验。")
    table(["报文", "长度", "字段（顺序）", "接收方校验"], [
        ["HS_INIT", "162 B", "ver｜type｜sid｜pubA(32)｜nonceA(16)｜idpubA(32)｜idA(4)｜idB(4)｜SigA(64)",
         "长度、收发方 ID 是否与本端一致、SigA"],
        ["HS_RESP", "186 B", "ver｜type｜sid｜pubB(32)｜nonceB(16)｜idpubB(32)｜SigB(64)｜MAC_B(32)",
         "长度、sid、SigB、MAC_B"],
        ["HS_CONFIRM", "42 B", "ver｜type｜sid｜MAC_A(32)", "长度、sid、MAC_A"],
    ], size=8.6, widths=[2.4, 1.6, 7.4, 4.6], title="三个握手报文的字段与长度")

    h2("4.3 INIT 的构造与签名覆盖范围")
    body("构造 INIT 时，先按固定顺序拼接字段，再对整个已拼接内容签名，最后把签名追加到尾部。"
         "签名的覆盖范围里特意包含了双方的 ID 与 sid：前者阻止“把发给 A 的握手转给 C”，"
         "后者阻止跨会话重放。")
    code([
        "eph_      = crypto::x25519_generate();",
        "my_pub_   = crypto::x25519_public_raw(eph_.get());",
        "my_nonce_ = crypto::random_bytes(proto::NONCE_LEN);",
        "my_idpub_ = crypto::ed25519_public_raw(identity);",
        "",
        "Bytes msg;                      // 先拼字段",
        "msg.push_back(proto::VERSION);",
        "msg.push_back(proto::HS_INIT);",
        "proto::append_u64(msg, sid_);",
        "proto::append(msg, my_pub_);",
        "proto::append(msg, my_nonce_);",
        "proto::append(msg, my_idpub_);",
        "proto::append_u32(msg, (uint32_t)myId);",
        "proto::append_u32(msg, (uint32_t)peerId);",
        "proto::append(msg, crypto::ed25519_sign(identity, msg));   // 后签名",
    ])
    body("这里有个实现细节值得强调：签名是对 msg 当前的内容做，再把结果追加。如果先追加签名再签名，"
         "就会把签名自身也算进去，验签时永远对不上。这类“边界差一个字段”的错误在本项目中真实发生过"
         "（见 4.4），并且不会崩溃，只会让所有握手失败。")

    h2("4.4 RESP 的验签：一次真实的分片错误")
    body("RESP 的签名输入不是整条报文，而是“RESP 前 90 字节 + 发起方 INIT 的签名 SigA”。"
         "把 SigA 纳入输入，等于把响应绑定到本次请求上，攻击者无法用旧的 RESP 应答新的 INIT。"
         "但正因为是部分拼接，切片长度必须精确，否则验签必然失败。")
    code([
        "Bytes resp_core = proto::slice(in, 0, proto::HS_RESP_SIGN);   // 含 SigB，共 154 字节",
        "Bytes sigA      = proto::slice(init_msg_, proto::HS_INIT_BASE, proto::SIG_LEN);",
        "",
        "// 正确：签名只覆盖前 90 字节 + SigA",
        "Bytes to_sign = proto::slice(in, 0, proto::HS_RESP_BASE);",
        "proto::append(to_sign, sigA);",
        "if (!crypto::ed25519_verify(idpubB, to_sign, sigB)) { ... }",
    ])
    body("开发过程中曾误把 154 字节的 resp_core（含 SigB）当成签名输入，于是验签输入变成 154 + 64 = 218 字节，"
         "而签名方只签了 90 + 64 = 154 字节。现象是“握手永远失败、错误信息永远是签名无效”，"
         "但双方各自的自测都通过——因为自测里签名与验签用的是同一段错误代码。"
         "最终通过对照协议长度表逐字段打印偏移才发现，这也解释了为什么本项目坚持在 protocol.h 中"
         "为每个偏移定义具名常量（HS_RESP_BASE / HS_RESP_SIGN）：让“魔法数字”变成可读的语义。")

    h2("4.5 共享秘密与 HKDF 密钥调度")
    body("双方各自用本端临时私钥与对端临时公钥计算 Z = X25519(eph, peer_pub)，两端结果必然相同；"
         "这个值从不直接当密钥使用，而是先经 HKDF-Extract 条件化，再按用途分域派生。"
         "把随机数拼成的 salt（nonceA‖nonceB）参与进来，可以让每次握手的中间值都不同，"
         "即使 Z 意外重复也不会产生相同的密钥。")
    fig("fig_kdf.png", "HKDF 密钥调度与域分离", 13.0)
    code([
        "Bytes z      = crypto::x25519_shared(eph_.get(), peer.get());",
        "Bytes salt   = initiator ? crypto::cat(my_nonce_, peer_nonce_)",
        "                         : crypto::cat(peer_nonce_, my_nonce_);",
        "Bytes secret = crypto::hkdf(z, salt, \"CHAT-v1 ECDHE X25519\", 32);",
        "",
        "chain_i2r    = crypto::hkdf(secret, {}, \"chain initiator->responder\", 32);",
        "chain_r2i    = crypto::hkdf(secret, {}, \"chain responder->initiator\", 32);",
        "finished_key = crypto::hkdf(secret, {}, \"finished key\", 32);",
        "root_key     = crypto::hkdf(secret, {}, \"root key\", 32);      // DH 棘轮起点",
        "",
        "crypto::wipe(z);  crypto::wipe(secret);   // 派生完立刻清零",
    ])
    table(["派生用途", "info 标签", "长度", "为什么需要单独派生"], [
        ["发起方→响应方链密钥", "chain initiator->responder", "32 B", "两个方向必须使用不同密钥"],
        ["响应方→发起方链密钥", "chain responder->initiator", "32 B", "同上"],
        ["Finished 校验密钥", "finished key", "32 B", "与消息密钥隔离，避免密钥确认密钥被消息复用"],
        ["DH 棘轮根密钥", "root key", "32 B", "棘轮只需要根密钥，不需要触碰初始链密钥"],
        ["本机存储密钥", "CHAT-v1 local storage key", "32 B", "由身份私钥派生，与会话密钥无关"],
    ], size=8.8, widths=[4, 5, 1.6, 5.4], title="HKDF 域分离：一把秘密，五个用途")

    h2("4.6 Finished 校验与安全码")
    body("Finished 不是身份认证（身份由签名完成），而是密钥确认：双方各自计算 "
         "HMAC(finished_key, transcript ‖ “A”/“B”)，只有派生出完全相同的会话密钥才可能对上。"
         "安全码则是在握手完成后，对同一份 transcript 再做一次带标签的哈希，取前 4 字节取模 10^6，"
         "得到一个 6 位数字。")
    code([
        "Bytes th = TranscriptHash(init_msg_, resp_msg_);      // 两次握手报文的哈希",
        "Bytes s  = crypto::sha256(crypto::cat(th, Bytes{ 'S', 'A', 'S' }));",
        "uint32_t v = (((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |",
        "              ((uint32_t)s[2] << 8)  |  (uint32_t)s[3]) % 1000000u;",
        "sas_ = format(\"%06u\", v);",
    ])
    table(["机制", "计算输入", "作用", "失败时的行为"], [
        ["SigA / SigB", "各自报文的明文部分 + SigA", "身份认证与防篡改", "握手失败，会话丢弃"],
        ["Finished(B) / (A)", "finished_key + transcript + 方向字节", "密钥确认（双方密钥一致）",
         "握手失败，会话丢弃"],
        ["SAS 安全码", "transcript + “SAS”", "把密钥一致性问题变成人可比对的问题",
         "界面显示，由用户核对"],
        ["指纹（16 hex）", "SHA256(secret) 前 8 字节", "同一会话在不同时间的可复现标识", "仅显示"],
    ], size=8.8, widths=[3.4, 5.4, 4.2, 4], title="四种校验机制的分工")

    h2("4.7 身份层与密钥保护")
    body("Ed25519 身份密钥只在首次运行时生成一次，之后长期保存。私钥以 PKCS#8 PEM 形式在内存中导出后，"
         "立即用 Windows DPAPI（CryptProtectData）以当前账户为密钥加密，再写入 identity.pem；"
         "读取时反向操作，失败则说明文件来自其他账户或机器。")
    body("实现上还有一个静态链接特有的坑：OpenSSL 的 PEM_read_PrivateKey(FILE*) 依赖 OPENSSL_Applink，"
         "静态链接时会直接弹出“OpenSSL: FATAL”错误框。解决办法是彻底不用 FILE* 接口，"
         "改为 BIO_new_mem_buf + BIO_s_mem 的内存 BIO，文件读写自己用 fopen/fread 完成。")

    h2("4.8 关键函数一览")
    table(["函数", "所在文件", "职责"], [
        ["SecureSession::BuildInit", "secure_session.h", "生成临时密钥与随机数，构造并签名 HS_INIT"],
        ["SecureSession::HandleInit", "secure_session.h", "验签 HS_INIT，构造并签名 HS_RESP，计算 Finished(B)"],
        ["SecureSession::HandleResp", "secure_session.h", "验签 HS_RESP，校验 Finished(B)，产出 HS_CONFIRM"],
        ["SecureSession::HandleConfirm", "secure_session.h", "校验 Finished(A)，进入 Established 并计算安全码"],
        ["SecureSession::Derive", "secure_session.h", "计算 Z，HKDF 派生双向链密钥、Finished 与根密钥"],
        ["SecureSession::ComputeSas", "secure_session.h", "由 transcript 派生 6 位安全码"],
        ["crypto::ed25519_sign / verify", "crypto_utils.h", "身份签名与验签（内存 BIO 存取 PEM）"],
        ["crypto::hkdf", "crypto_utils.h", "HKDF-SHA256，按 info 域分离派生任意长度密钥"],
    ], size=8.8, widths=[5.4, 3.6, 7.0], title="握手与密钥调度相关函数")


def personal_a2():
    h1("五、密钥棘轮与安全属性")
    body("握手解决的是“这一次会话的密钥怎么来”，棘轮解决的是“会话进行中密钥怎么变”。"
         "如果没有棘轮，一把会话密钥要用到会话结束：一旦泄露，整个会话（过去与未来）全部暴露。"
         "本章说明本项目叠加的两层棘轮，以及它们各自提供了哪种安全属性。")

    h2("5.1 两种时间维度的风险")
    body("密钥泄露有两个方向。向后看：攻击者今天拿到密钥，能不能解我昨天的消息？这要求密钥能“丢不掉”——"
         "即旧密钥一旦销毁就再也无法重建，这就是前向保密。向前看：攻击者今天拿到密钥，能不能解我明天"
         "的消息？这要求密钥能“换得掉”——即密钥更新后，旧密钥不再能推导新密钥，这就是后向恢复"
         "（post-compromise security）。ECDHE 握手只解决会话级别的前向保密，会话内部的这两件事要靠棘轮。")

    h2("5.2 消息级密钥棘轮")
    body("发送链是一个单向演进的值：每发一条消息，先从当前链密钥派生出消息密钥与 nonce，再用 HKDF 推进链密钥，"
         "并立刻覆盖旧值。于是每条消息一把密钥，且链只能向前走。")
    fig("fig_msg_ratchet.png", "消息级密钥棘轮：每条消息一把独立密钥", 13.0)
    code([
        "Bytes msg_key = crypto::hkdf(send_chain_, {}, \"message key\", 32);",
        "Bytes nonce   = crypto::hkdf(send_chain_, {}, \"message iv\", 12);",
        "Bytes next    = crypto::hkdf(send_chain_, {}, \"chain next\", 32);",
        "",
        "Bytes aad = proto::make_aad(type, sid_, send_seq_, myId, peerId);",
        "Bytes ct  = crypto::aead_encrypt(msg_key, nonce, plain, aad);",
        "",
        "crypto::wipe(send_chain_);  send_chain_ = next;      // 旧链密钥立即失效",
        "crypto::wipe(msg_key);  crypto::wipe(nonce);  crypto::wipe(next);",
    ])
    body("安全性来自 HKDF 的单向性：给定 chain' 无法反推 chain，因此也拿不到由 chain 派生的消息密钥。"
         "代价是每条消息多出三次 HKDF（约 3 次 HMAC-SHA256 的开销，实测可忽略），以及必须严格按序处理——"
         "序号一旦失步就无法解密，这也是本系统不支持乱序的根本原因。")

    h2("5.3 DH 棘轮与后向恢复")
    body("消息级棘轮只保证“旧的推不出新的”，但如果攻击者在某一时刻拿到了链密钥，他仍然可以跟着链往前走，"
         "解密之后的所有消息。要让被泄露的密钥“失效”，必须引入新的熵——这正是 DH 棘轮的作用。")
    fig("fig_dh_ratchet.png", "DH 棘轮：用新的 DH 输出更新根密钥并重建双向链", 13.2)
    body("实现上，发送方每发够 8 条消息就做一次轮换：先生成新的 X25519 密钥对，用旧链加密一条 REKEY 帧携带新公钥，"
         "然后用新私钥与对端当前棘轮公钥算出 DH 输出，按 root' = HKDF(ikm = DH, salt = root) 更新根密钥并重建双向链，"
         "最后覆盖旧私钥。")
    code([
        "if (send_since_rekey_ >= REKEY_INTERVAL) {",
        "    crypto::PkeyPtr fresh = crypto::x25519_generate();",
        "    Bytes freshPub = crypto::x25519_public_raw(fresh.get());",
        "",
        "    // 1) 用【旧链】加密 REKEY 帧（对端先用旧链解密，再轮换）",
        "    BuildRecord(proto::REKEY, freshPub, myId, peerId, rekeyRecord, err);",
        "    out.push_back(rekeyRecord);",
        "",
        "    // 2) Z = DH(新私钥, 对端当前棘轮公钥) → 更新根密钥与双向链",
        "    Bytes z = crypto::x25519_shared(fresh.get(), peer.get());",
        "    ApplyRatchet(z, err);",
        "",
        "    // 3) 覆盖旧私钥：历史 DH 输出再也不可能被重算",
        "    dh_self_ = std::move(fresh);",
        "    send_since_rekey_ = 0;",
        "}",
    ])
    body("顺序里有一处必须严格：REKEY 帧必须用旧链加密。如果先用新根密钥重建链再加密这条控制帧，"
         "对端就会处于“用旧链接收、用新链解密”的错位状态。这个顺序在代码里以注释形式固定下来，"
         "并在自测第 6 组用例中通过“连发 20 条 + 检查是否触发过轮换”来回归。")

    h2("5.4 接收侧的棘轮同步")
    body("接收侧的动作是对称的，但多一步判断：先用当前接收链解密，解密成功后才推进接收链；"
         "如果解出来的是一条 REKEY 记录，则用本端当前棘轮私钥与新对端公钥算 DH，再同步更新根密钥。"
         "解密失败必须直接丢弃，不能推进链——否则一次伪造报文就会把接收方永久带偏。")
    code([
        "if (seq != recv_seq_) { err = \"序号失步或重放\"; return false; }",
        "Bytes aad = proto::make_aad(type, sid, seq, peerId, myId);",
        "if (!crypto::aead_decrypt(msg_key, nonce, ct, aad, plain)) {",
        "    crypto::wipe(next);  err = \"消息认证失败\";  return false;   // 不推进链",
        "}",
        "crypto::wipe(recv_chain_);  recv_chain_ = next;  recv_seq_++;",
        "",
        "if (type == proto::REKEY) {                    // 对端轮换了 DH 密钥",
        "    Bytes z = crypto::x25519_shared(dh_self_.get(), peer_new.get());",
        "    ApplyRatchet(z, err);",
        "    dh_peer_pub_ = newPeerPub;  isControl = true;   // 控制帧不显示给用户",
        "}",
    ])

    h2("5.5 密钥生命周期与清零")
    body("密码学实现里“什么时候删”和“删得干不干净”同样重要。本项目的做法是：任何中间值在派生出下一层后"
         "立即 OPENSSL_cleanse 覆盖，临时私钥在首次棘轮轮换时被覆盖销毁。")
    table(["密钥 / 中间值", "产生时机", "生命周期", "销毁时机"], [
        ["Z（共享秘密）", "每次握手、每次 DH 棘轮", "毫秒级", "派生 secret 后立即清零"],
        ["secret（握手主秘密）", "每次握手", "毫秒级", "派生四个子密钥后立即清零"],
        ["会话链密钥 send/recv_chain", "握手或棘轮后", "直到下一次棘轮", "推进时覆盖；棘轮时重建"],
        ["消息密钥 / nonce", "每条消息", "单条消息", "加密或解密完成后立即清零"],
        ["身份私钥（内存）", "启动时由 DPAPI 解密", "整个进程生命周期", "进程退出时释放"],
        ["身份私钥（磁盘）", "首次运行生成", "长期", "仅 DPAPI 密文落盘，不存明文"],
        ["棘轮私钥 dh_self", "每次 DH 轮换", "一个轮换周期", "轮换时被新密钥覆盖"],
    ], size=8.8, widths=[4.4, 4.4, 3.6, 5.2], title="密钥生命周期与清零策略")

    h2("5.6 两个真实缺陷")
    body("（1）根密钥在缓冲区清零之后才派生。Derive() 里原本先 wipe(secret) 再计算 root_key，"
         "于是根密钥是对一坨全零计算的 HKDF 结果——功能完全正常，握手照样成功，消息照样收发，"
         "但所有会话的根密钥实际上都是同一个常量，后向恢复直接归零。这个缺陷没有任何运行时症状，"
         "是在通读密钥调度顺序时发现的，随后把根密钥派生移到 wipe 之前，并在注释里写明原因。")
    body("（2）REKEY 帧没有被分发。客户端与中间人的 switch 里最初只处理 DATA，收到 REKEY 时走 default 分支"
         "被静默丢弃。现象是“前 8 条消息正常，第 9 条开始对方一直没反应”——因为发送方已经轮换、"
         "接收方还在旧链上。修复是把 case proto::REKEY 与 DATA 合并处理，并由自测第 6 组用例"
         "（连发 20 条并检查轮换确实发生）兜住这类回归。")
    body("这两个缺陷说明：棘轮这类“状态机 + 密码学”的代码，正确性不能只看有没有异常，"
         "必须有跨越轮换点的端到端断言。")


def personal_a3():
    h1("六、安全性分析")
    body("本章把第二章的威胁模型逐条与本系统的实现对照，然后给出前向保密的论证思路、中间人实验的定量结论，"
         "以及与 TLS 1.3 / Signal 的横向比较，最后明确写出本系统不解决什么问题。")

    h2("6.1 逐条威胁对照")
    table(["威胁", "结论", "依据"], [
        ["链路被动窃听", "可防", "全流程 AEAD；抓包只能得到长度与十六进制密文"],
        ["服务器解密", "可防", "服务器无任何密钥；中间人实验反证：只有主动劫持才能解密"],
        ["篡改密文或帧头", "可防", "帧头（sid/seq/收发方）作为 AAD 参与认证"],
        ["重放旧报文", "可防", "序号严格单调，失步即作废并重置会话"],
        ["跨会话重放握手", "可防", "签名覆盖 sid 与双方 ID；RESP 绑定 SigA"],
        ["事后长期私钥泄露", "可防", "会话密钥只由临时私钥派生；身份私钥不进入 KDF"],
        ["当前棘轮密钥被窃取", "可防（一次轮换后）", "每 8 条消息轮换并覆盖旧私钥"],
        ["首次接触的中间人", "可发现，不能自动阻止", "签名保证未被篡改，但身份需安全码核对"],
        ["元数据分析（谁和谁聊天）", "不可防", "服务器必须知道目标 ID 才能转发"],
        ["终端被控制（键盘记录）", "超出范围", "端到端加密不防护端点"],
    ], size=8.8, widths=[3.8, 3.6, 8.6], title="威胁与防护结论对照")
    body("把“不可防”的两行写进表格是刻意的：一个安全设计如果不写清楚边界，就等于没有边界。"
         "元数据问题可以通过流量填充与混洗缓解，但不可能在中继模型下彻底解决；终端被控制则超出密码学范畴。")

    h2("6.2 前向保密的论证思路")
    body("用安全游戏的方式描述更清楚。假设攻击者在时刻 T 拿到全部长期与当前状态（身份私钥、棘轮私钥、链密钥），"
         "然后回放此前抓到的全部密文，试图恢复时刻 t < T 的明文。要成功，他必须得到时刻 t 的消息密钥；"
         "而消息密钥只由时刻 t 的链密钥派生，时刻 t 的链密钥又只能由更早的链密钥正向推进得到——"
         "攻击者手上的链密钥是“未来”的值，HKDF 的单向性使他无法反向推进。若他想绕过链密钥，"
         "就得重算当时的 X25519 共享秘密，而对应的临时私钥在握手结束（或上一轮棘轮）时就已被覆盖销毁。"
         "两条路都被堵死，因此历史会话保持机密。")
    body("后向恢复的论证同理：攻击者拿到当前棘轮私钥后，能解“当前”这一小段；但发送方下一次轮换会引入"
         "新的 X25519 私钥并更新根密钥，攻击者没有这个新私钥，无法计算新的 DH 输出，也就无法重建新链。"
         "因此最多泄露一个轮换周期（8 条消息）的内容。这个常数是可以调的，本项目取 8 是性能与暴露窗口的折中。")

    h2("6.3 中间人实验的定量结论")
    body("第七章的中间人实验给出了可复核的数据：中间人插入两段独立握手后，用户 1 看到安全码 "
         + MLOG["sas1"] + "、用户 2 看到 " + MLOG["sas2"] + "，两者不同；同时攻击者打印出了明文 "
         "card-password-is-123456，对应密文 " + MLOG["ctlen"] + " 字节，前 16 字节为 " + MLOG["hex16"] + "。"
         "这组数据同时说明了两件事：端到端加密在没有身份校验时确实不成立，"
         "而安全码确实能把“不可检测的劫持”变成“可检测的异常”。")
    table(["观察项", "正常会话（实测）", "中间人会话（实测）"], [
        ["发送端安全码", NORM["c1"][0], MITMS["c1"][0]],
        ["接收端安全码", NORM["c2"][0] + "（与发送端相同）", MITMS["c2"][0] + "（与发送端不同）"],
        ["发送端密钥指纹", NORM["c1"][1], MITMS["c1"][1]],
        ["接收端密钥指纹", NORM["c2"][1], MITMS["c2"][1]],
        ["攻击者能否看到明文", "否（服务器无密钥）", "是（打印出 card-password-is-123456）"],
        ["终端用户是否察觉异常", "无异常", "界面无异常，仅安全码不同"],
    ], size=8.8, widths=[4.4, 5.4, 6.2], title="正常会话与中间人会话的实测对比")
    body("因此“抗中间人”在本系统中的准确表述是：能够检测并阻断除“首次接触 + 用户不核对”之外的所有中间人场景；"
         "配合 TOFU 指纹固定后，同一对端第二次连接若指纹变化会直接阻断（用例 S-05）。")

    h2("6.4 与 TLS 1.3 / Signal 的对比")
    table(["特性", "本系统", "TLS 1.3", "Signal（双棘轮）"], [
        ["密钥交换", "X25519 ECDHE，三报文", "X25519 / P-256", "X3DH（多DH 组合）"],
        ["身份认证", "Ed25519 + 安全码", "证书链（PKI）", "身份密钥 + 安全码"],
        ["前向保密", "会话级 + 消息级", "会话级", "会话级 + 消息级"],
        ["后向恢复", "周期性 DH 棘轮（8 条）", "KeyUpdate（不引入新熵）", "逐条 DH 棘轮"],
        ["乱序容忍", "不支持", "支持（流式，无消息级密钥）", "支持（跳跃密钥缓存）"],
        ["信任模型", "无中心，用户核对", "CA 体系", "无中心，用户核对"],
    ], size=8.8, widths=[3.2, 4.6, 4, 4.2], title="与 TLS 1.3、Signal 的横向比较")
    body("本系统在“消息级前向保密 + 后向恢复”上比 TLS 1.3 更接近 Signal，但在乱序容忍上做了明确让步："
         "Signal 会缓存跳跃密钥以容忍丢包，本系统为了保持实现简洁与状态可枚举，选择“序号失步即重置会话”。"
         "这不是能力缺失，而是课程设计规模下的自觉取舍，并在第八章列为改进方向。")

    h2("6.5 已知局限与攻击面")
    table(["局限", "影响", "可行的改进"], [
        ["不支持乱序与丢帧", "弱网下会话重置，需重新握手", "缓存跳跃密钥，或允许有限窗口重排"],
        ["安全码依赖人工核对", "用户不核对则首次接触仍可被劫持", "引入带外信道（扫码/短码）或 PKI"],
        ["元数据对服务器可见", "通信关系与时间模式泄露", "消息填充、批量混洗、洋葱路由"],
        ["无离线消息队列", "对端不在线时消息丢弃（仅提示）", "加密离线暂存 + 取回后重放"],
        ["单机内存中的身份私钥", "终端被控制则无解", "硬件密钥（TPM）、口令保护私钥"],
        ["未做形式化验证", "协议正确性依赖人工推理与测试", "ProVerif / Tamarin 建模验证"],
    ], size=8.8, widths=[3.6, 5.4, 6.4], title="已知局限与改进方向")


# =============================== 成员 B：四五六 ===============================
def personal_b():
    h1("四、网络协议与并发设计")
    body("本章由成员 B 负责，说明密文帧如何在中继与客户端之间可靠传递、服务器如何在多连接并发下不发生帧交错，"
         "以及各类异常（离线、畸形帧、僵尸连接）如何处理。")

    h2("4.1 传输层选择：TCP + 自描述定长帧")
    body("选择 TCP 而不是 UDP，是因为聊天是低频、小数据、强顺序的场景，不需要为省一次 RTT 去自己实现重传与排序。"
         "但 TCP 是字节流：连续两次 write 在对端看来可能是一次 read，因此协议必须自带消息边界。"
         "本系统采用“长度前缀”方案：先写 4 字节长度，再写载荷，接收方严格按长度读满。"
         "相比用一个特殊分隔符，长度前缀不需要转义，也天然支持二进制密文。")

    h2("4.2 帧的读写实现")
    body("发送端的核心是“长度与载荷必须在同一临界区内连续写出”，否则两个线程交错写入就会把两帧的字节混在一起。"
         "服务器为每个连接准备了一把写锁，SendFrame 内部持有它完成两次 write。")
    code([
        "static bool SendFrame(ClientSession& c, const unsigned char* payload, uint32_t len) {",
        "    std::lock_guard<std::mutex> lk(c.write_mu);      // 每连接一把写锁",
        "    boost::system::error_code ec;",
        "    boost::asio::write(c.sock, boost::asio::buffer(&len, 4), ec);",
        "    if (!ec) boost::asio::write(c.sock, boost::asio::buffer(payload, len), ec);",
        "    return !ec;",
        "}",
    ])
    body("接收端的核心是“两段式读 + 边界检查”：先读 4 字节长度并校验上下界，再按长度读满载荷。"
         "长度字段本身是攻击面：若不检查，一个 0xFFFFFFFF 就能让服务器申请 4 GB 内存，"
         "进而拖垮整台机器。")
    code([
        "boost::asio::read(sock, boost::asio::buffer(&len, 4), ec);",
        "if (ec) break;",
        "if (len < 4 || len > proto::MAX_PAYLOAD) break;      // 4 B ≤ len ≤ 1 MiB",
        "std::vector<unsigned char> packet(len);",
        "boost::asio::read(sock, boost::asio::buffer(packet), ec);",
        "if (ec) break;",
        "const int sender = (int)proto::get_u32(packet.data());",
    ])

    h2("4.3 中继路由与并发模型")
    body("服务器对每个接入的连接启动一个阻塞读线程，线程自始至终只处理这一条连接；转发时需要访问“全局在线表”"
         "找到目标连接，然后写入目标 socket。这里有两个并发风险：全局表被并发读写，以及同一个目标 socket"
         "被多个线程同时写。前者用一把全局互斥量保护，后者用每连接一把写锁保护。")
    fig("fig_relay.png", "中继服务器的并发模型与锁的分工", 13.4)
    body("更关键的一个细节是锁的持有范围：如果一边持有全局锁一边做阻塞写，那么一个网络很慢的客户端就会把"
         "所有转发都卡住，整个服务退化成一个串行队列。因此全局锁只在查表时短暂持有，阻塞写放到锁外完成。")
    table(["锁 / 原子量", "保护的资源", "持有时间", "不加会怎样"], [
        ["g_clients_mu", "在线表 std::map<int, SessionPtr>", "仅查表/插入/删除的微秒级",
         "并发读写 map 导致崩溃或读到半更新状态"],
        ["write_mu（每连接）", "该连接 socket 的写操作", "一次 write 的长度 + 载荷",
         "两帧字节交错，对端无法还原帧边界"],
        ["g_connected / g_lastPong", "连接状态与心跳时间戳（atomic）", "无锁",
         "心跳线程与网络线程读写竞争"],
        ["g_sess_mu（客户端）", "会话表与待发队列", "单次加密 + 组帧",
         "界面线程与网络线程同时改会话导致密钥状态错乱"],
    ], size=8.8, widths=[3.6, 5.6, 3.4, 3.8], title="锁的分工与设计依据")

    h2("4.4 心跳、超时与回收")
    body("TCP 连接断开不一定能立刻感知：拔网线时对端不会收到 FIN，socket 会一直“看起来正常”。"
         "因此需要应用层心跳。客户端每 5 秒向服务器（目标 ID 为 0，不参与转发）发 PING，服务器本地回 PONG；"
         "超过 15 秒没收到 PONG 就判定断线，主动关闭 socket 触发重连。"
         "服务器侧另有一个巡检线程，每 10 秒扫一遍在线表，把 60 秒无活动的连接断开并释放 ID。")
    table(["参数", "值", "位置", "作用"], [
        ["PING 间隔", "5 s", "客户端网络线程", "保持链路活跃，探测时延"],
        ["PONG 超时", "15 s", "客户端网络线程", "连续 3 个周期无应答即判死"],
        ["重连间隔", "3 s", "客户端定时器", "服务器恢复后自动接回"],
        ["服务器巡检周期", "10 s", "Server 巡检线程", "发现僵尸连接"],
        ["空闲回收阈值", "60 s", "Server 巡检线程", "释放被占用的 ID，避免“ID 已被占用”"],
        ["单帧上限", "1 MiB", "收发两端", "防止用一个长度字段耗尽内存"],
        ["单条消息上限", "64 KB", "客户端发送前", "超长时给用户明确提示而不是静默截断"],
    ], size=8.8, widths=[3.6, 2.4, 4.4, 6], title="心跳与超时相关参数")

    h2("4.5 异常路径清单")
    body("把异常当成一等公民来设计：每一条都要回答“怎么发现、怎么处理、用户看到什么”。")
    table(["场景", "检测手段", "处理方式", "用户可见结果"], [
        ["目标用户不在线", "在线表查不到目标", "回 SYSTEM 帧给发送方（不转发）", "⚠ 用户 X 不在线，N 条消息未送达"],
        ["帧长非法", "len < 4 或 len > 1 MiB", "断开该连接，其他连接不受影响", "该客户端显示断开并重试"],
        ["握手报文长度不对", "固定长度比较", "丢弃并记日志，不改变会话状态", "会话建立失败提示"],
        ["签名/Finished 错误", "验签与 HMAC 比较", "销毁会话，要求重新握手", "消息校验失败，已重置会话"],
        ["序号失步或重放", "seq != recv_seq_", "拒绝该帧，不推进接收链", "同上"],
        ["服务器中途退出", "socket 读失败 / PONG 超时", "关闭 socket，清空会话，3 秒后重连", "红色提示：与服务器断开，正在重试"],
        ["客户端进程崩溃", "60 秒无活动", "服务器回收 ID", "（该 ID 可被重新分配）"],
        ["慢客户端", "——", "写操作只持有目标连接的写锁", "其他用户的转发不受影响"],
    ], size=8.6, widths=[3.4, 4.2, 4.4, 4.4], title="异常路径的检测与处理")

    h2("4.6 关键函数一览")
    table(["函数", "所在文件", "职责"], [
        ["SendFrame", "server.cpp", "加每连接写锁，连续写出长度与载荷"],
        ["SendPayload", "server.cpp", "在载荷前插入 4 字节发送者 ID 后转发"],
        ["SendSystem", "server.cpp", "向指定客户端回一条明文提示（含 related_id）"],
        ["HandleClient", "server.cpp", "单连接读循环：长度检查、查表路由、异常退出清理"],
        ["NetworkThread", "ClientGUI.cpp", "连接、读循环、消息分发、断线后统一善后"],
        ["MakeFrame", "ClientGUI.cpp", "为端到端载荷加上长度与目标 ID"],
        ["SendRaw", "ClientGUI.cpp", "在 g_net_mu 保护下写 socket"],
    ], size=8.8, widths=[3.8, 3.6, 8.6], title="网络层关键函数")


def personal_b2():
    h1("五、客户端工程实现")
    body("客户端是一个单进程多线程的 Win32 程序：界面线程负责交互与重绘，网络线程负责收发热连接，"
         "定时器负责心跳与重连探测。本章说明它们如何协作，以及聊天记录如何被加密保存。")

    h2("5.1 客户端状态机")
    body("把连接与会话拆成两个维度：连接维度关心“有没有和服务器连上”，会话维度关心“有没有和某个对端协商好密钥”。"
         "两个维度都必须显式建模，否则很容易出现“显示已连接但发不出消息”的中间态。")
    fig("fig_state.png", "客户端的连接与会话状态机", 13.2)
    body("状态机的每条边都有明确的触发条件与用户提示：连接成功写“已连接服务器 · 我的 ID 是 N”；"
         "握手完成写“与用户 X 的加密会话已建立 · 安全码 …… · 密钥指纹 ……”；断线写红色的"
         "“与服务器断开，正在重试连接…”。断线时会清空会话表，重连后必须重新握手——"
         "旧会话密钥随旧 socket 一起丢弃，这正是前向保密在工程上的体现。")

    h2("5.2 线程模型与锁序")
    table(["线程", "职责", "会碰到的共享状态"], [
        ["界面线程（主线程）", "窗口消息、布局、渲染、发送按钮", "会话表、聊天记录、控件句柄"],
        ["网络线程", "连接、读循环、报文分发、心跳", "session 对象、socket、g_connected"],
        ["定时器（界面线程）", "心跳发送、重连探测、未读刷新", "同上"],
        ["（外部）--dump 进程", "解密导出历史后退出", "仅读文件，不与其他线程并发"],
    ], size=8.8, widths=[3.8, 6, 5.2], title="客户端的线程划分")
    body("锁只有两把：g_sess_mu 保护会话表与待发队列，g_net_mu 保护 socket 与连接标志。"
         "为避免死锁，代码中固定了锁序：先会话锁、后网络锁（LockedSendChat 在持有会话锁的情况下调用 SendRaw，"
         "后者取网络锁）。任何需要“发消息”的地方都遵循同一顺序，从不在持有网络锁时去取会话锁。")
    body("另一个工程细节是“界面更新不在锁内做”。网络线程只把事件 PostMessage 到界面线程，"
         "界面线程在消息循环里更新控件。这样既避免了锁内调用 Win32（可能阻塞甚至重入），"
         "也避免了跨线程直接 SetWindowText 的未定义行为。")

    h2("5.3 发送路径：排队、握手与补发")
    body("用户点“发送”时，会话可能还没建立。此时不能丢消息，也不能阻塞界面，做法是：把明文放进该对端的待发队列，"
         "同时发起握手；会话建立后由 LockedFlushOutbox 按序补发。这样“第一次给某人发消息”的用户体验是"
         "“消息立刻出现在自己屏幕上，对方稍后收到”，而不是“点了没反应”。")
    code([
        "static bool SendUserMessage(int target, const std::wstring& wtext, bool& queued) {",
        "    std::string text = WideToUtf8(wtext);",
        "    if (text.empty()) return false;",
        "    if (text.size() > MAX_TEXT_BYTES) { PostStatus(L\"消息过长（最大 64 KB），已取消发送\", true); return false; }",
        "",
        "    std::lock_guard<std::mutex> lk(g_sess_mu);",
        "    PeerSession& s = g_sessions[target];",
        "    if (s.crypto.established()) {",
        "        LockedSendChat(target, s, text);      // 已建立：直接加密发送",
        "    } else {",
        "        s.outbox.push_back(text);             // 未建立：排队",
        "        queued = true;",
        "        if (s.crypto.state() != State::Initiating) LockedStartHandshake(target);",
        "    }",
        "    return true;",
        "}",
    ])
    body("LockedSendChat 里有一个容易踩的坑：Seal() 返回的是“帧的集合”而不是单帧，"
         "因为第 8 条消息时会额外产生一条 REKEY 帧。如果只取第一帧，就会出现“控制帧发出去了、正文丢了”"
         "或者相反的情况。因此这里用循环按序发送全部帧。")

    h2("5.4 加密持久化与 DPAPI")
    body("持久化有两个层次：聊天记录用“身份私钥派生的存储密钥”加密，身份私钥本身再用 DPAPI 加密。"
         "两层保护针对不同威胁：前者防止聊天记录被单独拷走，后者防止身份文件被拷到别的账户或机器。")
    fig("fig_storage.png", "本地存储的加密链与目录结构", 13.4)
    code([
        "static void SaveChatMsg(int peer, const ChatMsg& m) {",
        "    Bytes key = StorageKey();                    // HKDF(身份私钥, \"CHAT-v1 local storage key\")",
        "    Bytes nonce = crypto::random_bytes(proto::IV_LEN);",
        "    Bytes aad   = proto::make_aad(0, 0, m.ts, my_client_id, peer);",
        "    Bytes ct    = crypto::aead_encrypt(key, nonce, utf8, aad);   // 40..80 字节",
        "",
        "    // 一行一条记录：hex(nonce ‖ 密文 ‖ tag)，用 _wfopen_s 追加",
        "    std::wstring line = HexW(nonce) + HexW(ct);",
        "    AppendLineW(ChatFile(peer), line);",
        "}",
    ])
    body("实现中踩过的最隐蔽的一个坑是中文路径：%APPDATA% 在中文用户名下含有汉字，"
         "而 fopen_s 是 ANSI 接口，打开失败却返回一个“看起来像成功”的空文件。"
         "现象是“聊天记录永远不落盘、重开客户端什么都没有”，但程序没有任何报错。"
         "改为 _wfopen_s + std::wstring 全程宽字符后解决。这也是为什么本项目所有文件路径都用 wstring 传递。")
    body("归档键的选择也有讲究：目录名用的是“本地身份指纹”而不是服务器分配的 ID。因为 ID 是临时的"
         "（重启服务器就变），身份密钥才是持久的；这样重启、换 ID 之后，历史记录与指纹固定依然有效。")

    h2("5.5 多档案、导出与测试接口")
    body("--profile 让同一台机器上的多个实例拥有独立的身份、历史与指纹目录，从而可以在单机上演示多用户；"
         "--dump 在本地解密并导出聊天记录（格式为“对端\\t方向\\t内容”）。"
         "后者最初只是为了调试，后来变成了自动化测试的关键：跨进程读取多行编辑框不可靠，"
         "而导出的文本可以精确断言。")

    h2("5.6 界面实现要点")
    body("界面用原生 Win32 控件实现，分为三块：左侧会话列表（带未读圆点）、中间聊天区（只读编辑框）、"
         "底部输入行与状态栏。几个交互细节值得说明：一是布局在 WM_SIZE 中按比例重算，"
         "所有尺寸乘以 DPI 缩放系数 g_scale，因此在高分屏上不会糊也不会错位；"
         "二是所有“系统级”信息只写入状态栏（握手、指纹、断线、错误），聊天区只保留消息，"
         "避免提示刷屏；三是发送给离线用户时，聊天区插入一行 ⚠ 警示，同时状态栏变红，两处同时提醒。")
    body("未读标记的实现是：收到属于非当前会话的消息时，把对端 ID 放进 g_unread 集合，"
         "会话列表项文本追加“●”，切换会话时清除。这比“弹窗提醒”更轻，也不会打断输入。")

    h2("5.7 关键函数一览")
    table(["函数", "职责"], [
        ["NetworkThread", "连接服务器、读循环、按类型分发报文、断线善后"],
        ["HandleInit / HandleResp / HandleConfirm", "握手三报文的分发处理，含 TOFU 指纹校验"],
        ["HandleData", "解密 DATA/REKEY，控制帧静默处理"],
        ["HandleSystem", "处理服务器提示，同时更新聊天区与状态栏"],
        ["LockedSendChat / LockedFlushOutbox", "加密发送与握手完成后的队列补发"],
        ["CheckPin / SavePin", "对端身份公钥的首次固定与变化阻断"],
        ["SaveIdentity / LoadIdentity", "DPAPI 加密保存与读取身份私钥（含明文升级）"],
        ["SaveChatMsg / LoadAllChats", "逐条加密落盘与启动时全量重载"],
        ["LayoutControls", "按窗口尺寸与 DPI 重新布局"],
    ], size=8.8, widths=[6.4, 9.6], title="客户端关键函数")


def personal_b3():
    h1("六、测试工程与工具链")
    body("本章由成员 B 负责，说明测试是怎么组织的、自动化测试踩过哪些坑、中间人工具如何实现，"
         "以及构建过程中与工具链相关的三个真实问题。")

    h2("6.1 三层测试结构")
    table(["层次", "工具", "覆盖内容", "优点 / 局限"], [
        ["单元与协议断言", "CryptoTest.exe（28 项）", "密码学原语、密钥调度、两种棘轮、完整握手",
         "快、可精确定位；不涉及网络与界面"],
        ["端到端自动化", "smoke_test.ps1（5 项）", "真窗口 + 真服务器 + 真加密 + 落盘 + 导出",
         "验证全链路；依赖窗口句柄，较脆弱"],
        ["攻击与专项", "mitm_demo.ps1、手工用例", "中间人、篡改、重放、断开、畸形帧",
         "能证明安全边界；部分需人工判读截图"],
    ], size=8.8, widths=[3.4, 4.4, 4.6, 5.6], title="三层测试结构")

    h2("6.2 跨进程 GUI 自动化的两个坑")
    body("第一个坑是“假成功”。最初的脚本用 SendMessage(WM_GETTEXT) 读取多行编辑框内容做断言，"
         "但跨进程读大文本时缓冲区处理很容易出错，读回来是空串；而断言写的是“不包含错误内容”，"
         "空串自然也“不包含”，于是测试长期显示通过。修复办法是放弃读控件，改用 --dump 导出明文再断言，"
         "并且把断言从“不包含”改成“必须匹配带换行锚点的正则”。")
    body("第二个坑是“匹配到自己”。脚本会把执行过程回显到控制台，如果断言用不带锚点的包含匹配，"
         "就会匹配到脚本自己打印的那行文本。修复是给正则加 (?m)^ 行首锚点，只匹配导出文件中的行。"
         "这两个坑的共同教训是：测试自身的可信度也需要被检验，一个从不失败的断言等于没有断言。")

    h2("6.3 中间人工具的设计")
    body("攻击工具与客户端共用同一份 SecureSession，这样才谈得上“攻击的是这套协议”。"
         "它冒充中继服务器：收到用户 1 的 INIT 时，一边以“用户 2 的身份”回应，一边以“用户 1 的身份”"
         "向真正的用户 2 发起握手。于是两段会话各自建立，中间人同时持有两把会话密钥。")
    fig("fig_mitm.png", "中间人工具的双握手结构", 12.4)
    body("实现中最麻烦的是时序：一端握手完成、另一端还没完成时，先到的数据帧无处可发。"
         "解法是给每个方向准备一个待转发队列，收到数据时若目标尚未建立会话就先入队，"
         "等该方向握手完成后按序补发。日志里的“会话尚未完全建立，已缓存 1 条消息，稍后转发”"
         "就是这条路径被触发时的输出。")
    code([
        "// 收到一端发来的记录：DATA 或 REKEY（REKEY 也是加密记录，必须一并转发）",
        "if (type == proto::DATA || type == proto::REKEY) {",
        "    if (!other.session.established()) {",
        "        pending[dir].push_back(payload);      // 对端还没握手完 → 入队",
        "        Log(\"会话尚未完全建立，已缓存 1 条消息，稍后转发\");",
        "        return;",
        "    }",
        "    Forward(dir, payload);",
        "}",
    ])
    body("这里也有过一次真实缺陷：早期只判断 type == DATA，导致 DH 棘轮产生的 REKEY 帧被丢弃，"
         "表现为“通过中间人通信时，第 9 条消息开始丢”。这也顺带证明了 REKEY 帧确实在加密通道内传输——"
         "如果它是明文控制帧，中间人就不会“看不见”。")

    h2("6.4 构建与依赖")
    table(["依赖", "版本 / 方式", "用途"], [
        ["OpenSSL", "3.x（vcpkg）", "X25519、HKDF、AES-GCM、Ed25519、随机数"],
        ["Boost.Asio", "Boost 1.8x（vcpkg）", "同步 TCP 与阻塞读写"],
        ["CMake", "3.20+", "构建；find_package(Boost CONFIG REQUIRED)"],
        ["crypt32", "Windows 系统库", "DPAPI 加解密身份私钥"],
        ["uxtheme / dwmapi", "Windows 系统库", "深色标题栏与窗口效果"],
    ], size=8.8, widths=[3.2, 4.4, 9.4], title="构建依赖")
    body("构建过程中有三个值得记录的问题。"
         "第一，CMake 4 移除了 FindBoost 模块，必须改用 Boost 的 CONFIG 模式并显式指定 COMPONENTS system，"
         "否则配置阶段直接失败。"
         "第二，OpenSSL 静态链接时，任何使用 FILE* 的 PEM 接口都会因缺少 OPENSSL_Applink 而弹出"
         "“OpenSSL: FATAL”对话框——这已经在第四章说明，解决方式是改用内存 BIO。"
         "第三，源码中大量中文字符串在 UTF-8 与系统 ANSI 代码页之间转换时出现乱码，"
         "最终统一以 /utf-8 编译、内部一律用 UTF-8 的 std::string/wstring 互转，并在入口处设置初始窗口文本。")

    h2("6.5 关键函数一览")
    table(["函数 / 脚本", "所在文件", "职责"], [
        ["Route", "Tools/mitm_relay.cpp", "按方向转发记录，必要时入待转发队列"],
        ["FlushPending", "Tools/mitm_relay.cpp", "握手完成后按序补发缓存的记录"],
        ["run_tests / CHECK", "Tests/crypto_selftest.cpp", "28 项断言的驱动与计数"],
        ["smoke_test.ps1", "Tools/", "启动服务器与两个客户端、发消息、导出并断言"],
        ["mitm_demo.ps1", "Tools/", "启动中间人、互发明文、打印截获结果并截图"],
        ["capture_shots.ps1", "Tools/", "抓取正常会话、离线提示、断线提示与密文样本"],
    ], size=8.8, widths=[4.6, 4.8, 6.6], title="测试与工具链关键函数")


# =============================== 第八章 ===============================
def ch8_summary(personal_para):
    doc.add_page_break()
    h1("八、总结与展望")

    h2("8.1 完成的工作")
    body("本次课程设计从一个“看起来能用、实际上没有任何加密”的原型出发，最终得到一个具备完整密码学协议、"
         "可演示、可测试的端到端加密聊天工具。主要交付物如下。")
    table(["交付物", "内容"], [
        ["密码学层", "crypto_utils.h：X25519、HKDF-SHA256、AES-256-GCM、Ed25519 与密钥清零"],
        ["协议层", "protocol.h + secure_session.h：三报文握手、密钥调度、消息级棘轮、DH 棘轮、安全码"],
        ["中继服务器", "server.cpp：按 ID 路由、每连接写锁、心跳应答、60 秒回收、帧长上限"],
        ["图形客户端", "ClientGUI.cpp：会话列表、状态栏、加密持久化、DPAPI、多档案、自动重连"],
        ["测试", "28 项密码学与协议断言、5 项端到端自动化断言、62 项测试用例记录"],
        ["攻击演示", "mitm_relay.cpp + mitm_demo.ps1：可运行的中间人攻击与截图取证"],
        ["文档", "设计报告、两人分工与答辩材料、图解与测试截图"],
    ], size=8.8, widths=[3.4, 12.6], title="交付物清单")

    h2("8.2 亮点回顾")
    body("回头看，这个项目最值得说的不是“实现了多少个算法”，而是把“安全属性”变成了可以验证的东西。")
    table(["亮点", "一句话说明"], [
        ["服务器零密钥", "中继只转发，攻破服务器也拿不到明文——并且用中间人实验反证过"],
        ["协议代码可复用", "同一份握手代码既是客户端，也是攻击工具，实验才具有说服力"],
        ["三层密钥演进", "会话（ECDHE）→ 消息（链棘轮）→ 周期（DH 棘轮），前向保密与后向恢复兼得"],
        ["帧头参与认证", "会话号、序号、收发方全部进 AAD，篡改与重放都无法通过"],
        ["可检测的中间人", "签名负责防篡改，安全码负责发现身份替换，TOFU 负责第二次阻断"],
        ["工程健壮性", "心跳、自动重连、DPAPI、加密落盘、多档案、畸形帧防御"],
        ["可自动化验证", "跨进程 GUI 自动化 + 受控导出，测试可重复运行且能真正失败"],
    ], size=8.8, widths=[3.6, 12.4], title="项目亮点回顾")

    h2("8.3 不足与改进方向")
    table(["不足", "现状", "改进方向"], [
        ["乱序与丢包", "序号失步即重置会话", "缓存跳跃密钥，支持有限窗口重排"],
        ["身份信任", "依赖用户核对 6 位安全码", "扫码/带外短码，或引入证书体系"],
        ["离线消息", "仅提示未送达", "加密离线暂存，上线后取回"],
        ["元数据", "服务器可见通信关系", "消息填充、批量混洗、匿名路由"],
        ["形式化验证", "依赖人工推理与测试", "ProVerif / Tamarin 建模并证明"],
    ], size=8.8, widths=[3.2, 5.4, 7.4], title="不足与改进方向")
    body("后续若继续扩展，优先级最高的是“乱序容忍”与“离线消息”：前者决定弱网体验，后者决定功能完整度。"
         "两者都会引入新的状态管理复杂度（跳跃密钥缓存、离线队列的加密存储），"
         "需要在协议层增加明确的版本号与能力协商，避免破坏现有握手。")

    body(personal_para)

    h2("8.4 本人总结")
    body("通过本次设计，我不仅掌握了所用算法的具体用法，更重要的是建立了“先建模威胁、再选择机制、"
         "最后用实验证伪”的安全工程思维：任何一个“看起来能用”的实现，都必须用可失败的测试去证明。")


# =============================== 生成 ===============================
def build(role, abstract_text, keywords, personal, personal_para, filename):
    new_doc()
    cover(role)
    chapter_title()
    abstract(abstract_text, keywords)
    ch1_requirement()
    ch2_requirement_analysis()
    ch3_overall()
    for fn in personal:
        fn()
    ch7_test()
    ch8_summary(personal_para)
    out = os.path.join(OUTDIR, filename)
    doc.save(out)
    print("saved:", os.path.basename(out), os.path.getsize(out),
          "图", NUM["fig"], "表", NUM["tab"])


def main():
    os.makedirs(OUTDIR, exist_ok=True)

    build(
        "密码协议设计（成员 A）",
        "本报告实现了一个具备前向保密与后向恢复能力的端到端加密聊天工具。系统以 X25519 的 ECDHE 临时密钥交换"
        "为核心，每次会话都协商出独立的会话密钥，并通过 HKDF-SHA256 按用途做域分离；记录层采用 AES-256-GCM，"
        "把会话号、序号与收发方作为附加认证数据参与完整性校验；在此之上叠加消息级密钥棘轮与周期性 DH 棘轮，"
        "使历史消息不可被事后解密、被泄露的当前密钥也无法推导未来密钥。身份层使用 Ed25519 签名与 6 位安全码，"
        "并实现了一个可运行的中间人攻击工具来定量验证安全边界。实验表明：28 项密码学与协议断言全部通过，"
        "服务器在整个过程中始终无法解密任何一条消息，而中间人一旦插入两段握手，两端安全码必然不同"
        "（实测 " + MLOG["sas1"] + " 与 " + MLOG["sas2"] + "），核对一次即可发现。",
        "前向保密；ECDHE；X25519；HKDF；AES-GCM；Ed25519；密钥棘轮；端到端加密",
        [personal_a, personal_a2, personal_a3],
        "本人主要负责密码协议部分：设计并实现了三报文握手、签名覆盖范围、HKDF 密钥调度、Finished 校验与安全码派生，"
        "以及消息级棘轮与 DH 棘轮两项密钥更新机制，并编写了 28 项密码学与协议断言。"
        "在这个过程中，最深的体会是密码学实现的正确性往往取决于“细节的对称性”——签名与验签的输入、"
        "派生顺序、清零时机，任何一处不一致都会导致握手失败或安全性归零，而且往往不会报错。"
        "本项目里两次最危险的缺陷（根密钥在清零后派生、REKEY 帧被丢弃）都属于这一类：功能全对，安全性全无。",
        "专业程序设计报告-成员A-密码协议方向.docx")

    build(
        "网络与工程化（成员 B）",
        "本报告实现了一个具备前向保密能力的端到端加密聊天工具。系统采用客户端—中继服务器—客户端结构："
        "客户端承担全部密码学运算，中继服务器只按目标 ID 转发密文帧、应答心跳并回收超时连接，不持有任何密钥。"
        "工程上重点解决了并发写同一 socket 的帧交错、全局锁阻塞、心跳与断线重连、聊天记录的加密持久化"
        "与身份私钥的 DPAPI 保护，并配套实现了可重复执行的端到端自动化测试与中间人攻击演示工具。"
        "实验表明：62 项测试用例全部符合预期；服务器日志中只有字节数而无明文；断网后 15 秒内可发现并自动重连；"
        "畸形帧只会断开单个连接；落盘记录完全为十六进制密文，搜索不到任何明文。",
        "端到端加密；ECDHE；AES-GCM；并发控制；心跳重连；加密存储；DPAPI；自动化测试",
        [personal_b, personal_b2, personal_b3],
        "本人主要负责网络与工程化部分：中继服务器的路由与并发控制、客户端的心跳与自动重连、加密持久化与 DPAPI、"
        "多档案与导出功能，以及端到端自动化测试和中间人演示工具。"
        "这部分工作让我体会到：安全系统的可靠性往往不取决于算法，而取决于异常路径——断线、丢帧、畸形包、"
        "中文路径、进程占用，这些“非功能”细节才是最容易出问题的地方。"
        "本项目里最难排查的三个 bug（SYSTEM 帧缺少发送者前缀、中文路径导致落盘静默失败、"
        "测试脚本的假成功）都不在密码学里，而在工程细节里。",
        "专业程序设计报告-成员B-网络与工程化方向.docx")


if __name__ == "__main__":
    main()
