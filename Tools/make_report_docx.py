# -*- coding: utf-8 -*-
"""按“专业程序设计报告模板.docx”的版式生成课程设计报告。"""
import os
import sys
from docx import Document
from docx.shared import Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn

TEMPLATE = r"C:\Users\陈浩然\Desktop\一些文件\大四上实践周\专业程序设计报告模板.docx"
OUTDIR = r"D:\ECDHE-Secured Chat System\docs"
OUT = os.path.join(OUTDIR, "专业程序设计报告-基于ECDHE的前向保密聊天工具.docx")
IMG1 = os.path.join(os.environ.get("TEMP", "."), "mitm_demo", "client_1.png")
IMG2 = os.path.join(os.environ.get("TEMP", "."), "mitm_demo", "client_2.png")

doc = Document(TEMPLATE)

# ---------- 清空模板正文（保留节属性/页面设置） ----------
body = doc.element.body
for child in list(body):
    if child.tag == qn('w:sectPr'):
        continue
    body.remove(child)


# ---------- 基础排版helper ----------
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
    return para(text, size=14, bold=True, indent=0, line=1.5, before=14, after=8)


def h2(text):
    return para(text, size=12, bold=True, indent=0, style='Body Text', before=8, after=4)


def body(text, indent=24):
    return para(text, size=12, indent=indent, line=1.5)


def code(lines):
    for ln in lines:
        p = doc.add_paragraph(style='Normal')
        p.paragraph_format.first_line_indent = Pt(0)
        p.paragraph_format.left_indent = Pt(18)
        p.paragraph_format.line_spacing = 1.0
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(ln if ln else " ")
        _font(r, "Consolas", "宋体", 9)
    doc.add_paragraph()


def caption(text):
    p = doc.add_paragraph(style='Caption')
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(text)
    _font(r, "Times New Roman", "宋体", 10.5)
    return p


def table(headers, rows, size=10, widths=None):
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


def picture(path, width_cm=14.5):
    if os.path.exists(path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run().add_picture(path, width=Cm(width_cm))
    else:
        para("（此处置入运行截图）", 10.5, align=WD_ALIGN_PARAGRAPH.CENTER, indent=0)


# ============================ 封面 ============================
para("专业课程设计报告", size=36, align=WD_ALIGN_PARAGRAPH.CENTER, indent=0,
     ea="黑体", ascii_name="黑体", before=40)
para("（ 2026/ 2027 学年 第 一 学期）", size=15, align=WD_ALIGN_PARAGRAPH.CENTER,
     indent=0, ea="黑体", ascii_name="黑体", before=8)
para("", size=12, indent=0)
para("题   目：基于 ECDHE 的前向保密聊天工具", size=22, indent=54,
     ea="黑体", ascii_name="黑体", before=30)
para("", size=12, indent=0)
para("姓   名：________________", size=16, indent=54, ea="黑体", ascii_name="黑体", before=24)
para("学   号：________________", size=16, indent=54, ea="黑体", ascii_name="黑体", before=8)
para("专   业：________________", size=16, indent=54, ea="黑体", ascii_name="黑体", before=8)
para("指导教师：________________", size=16, indent=54, ea="黑体", ascii_name="黑体", before=8)

doc.add_page_break()

# ============================ 正文 ============================
para("基于 ECDHE 的前向保密聊天工具", size=16, bold=True,
     align=WD_ALIGN_PARAGRAPH.CENTER, indent=0, before=6, after=12)

# ---------------- 一 ----------------
h1("一、课题内容和要求")

h2("课题内容")
body("本课题围绕“前向保密（Forward Secrecy）”这一密码学安全属性展开。前向保密指长期使用的主密钥泄露"
     "不会导致历史会话密钥泄露，即使系统遭到主动攻击也是如此。课题要求设计并实现一个具备前向安全性的"
     "即时通信工具：通信双方在通信开始前，通过椭圆曲线迪菲-赫尔曼临时密钥交换协议（ECDHE）协商出本次"
     "会话专用的密钥，并使用该密钥对聊天内容进行对称加密。程序要求使用 Windows 平台的图形界面实现，"
     "支持多客户端同时在线并点对点通信，且中继服务器不得具备解密能力。")

h2("课题要求")
body("（1）理解消息安全通信工具的基础概念和工作原理，明确机密性、完整性、身份认证与前向保密之间的区别与联系。")
body("（2）理解前向保密的基础理论，掌握 ECDHE 为什么能够提供前向保密，以及它与 RSA 密钥交换的本质差异。")
body("（3）采用传输层安全协议（TLS）中的相关加密套件，通过整合支持前向安全性的算法（如 ECDHE）保证每次会话都生成独立的会话密钥。")
body("（4）完成一个可运行、可演示的图形化聊天工具，并通过实验证明：即使长期主密钥泄露，历史通信依然安全。")

# ---------------- 二 ----------------
h1("二、需求分析和总体设计")

h2("需求分析")
body("该课题需要实现一个以 ECDHE 为核心、具备前向保密能力的端到端加密通信系统。在动手实现之前，先明确"
     "系统面对的威胁模型，再据此推导功能需求与非功能需求。")
body("（1）威胁模型。系统需要抵御的攻击者能力与对应的设计响应如下表所示。")
table(["攻击者能力", "系统设计响应"], [
    ["被动窃听链路（抓包）", "全程 AEAD 加密，攻击者只能得到密文与长度"],
    ["攻破中继服务器", "服务器不持有任何密钥，无法解密；篡改会破坏 AAD 认证"],
    ["主动中间人（替换公钥）", "Ed25519 签名 + Finished 校验阻断篡改；首次接触靠安全码核对"],
    ["重放、篡改、乱序", "帧头（会话号、序号、收发方）作为 AAD 参与认证，序号严格单调"],
    ["事后获取长期主密钥", "会话密钥只由临时私钥派生，历史会话不可还原（前向保密）"],
    ["当前棘轮密钥被窃取", "每 8 条消息触发 DH 棘轮轮换，旧私钥即时销毁（后向恢复）"],
    ["本机文件被拷贝", "身份私钥 DPAPI 加密，聊天记录 AES-GCM 加密，换账户不可解密"],
    ["进程崩溃、断网", "心跳 15 秒判定超时自动重连，服务器 60 秒回收僵尸连接"],
], size=9.5, widths=[5.5, 10])

body("（2）功能需求。① 多客户端在线，按 ID 点对点通信；② 消息端到端加密且服务器不可解密；"
     "③ 会话列表与聊天记录持久化，重启自动重载；④ 断线自动重连、离线提示与失败反馈；"
     "⑤ 可验证的对端身份（安全码与指纹固定）。")
body("（3）非功能需求。安全性方面要求具备机密性、完整性、前向保密、抗重放以及（配合安全码的）抗中间人能力；"
     "性能方面要求单次握手在局域网内小于 10 毫秒；可用性方面要求断网后 15 秒内发现并自动恢复；"
     "可维护性方面要求密码学层与网络层解耦，协议实现能被测试工具复用。")

h2("总体设计")
body("1、实验环境：Windows 11（x64）。")
body("2、实验工具：Visual Studio 2022、CMake 3.20 及以上、vcpkg 包管理器（openssl、boost-asio）。")
body("3、实验语言：C++17，网络层使用 Boost.Asio，密码学层使用 OpenSSL 3.x 的 EVP 接口。")
body("4、程序整体功能如图 1 所示（客户端聊天界面与安全状态栏）。")
picture(IMG1, 13.5)
caption("图 1 客户端主界面与安全状态栏")
body("（1）交互界面：左侧为按对端分组的会话列表，中间为聊天记录区，底部为收件人、输入框与发送按钮，"
     "最下方状态栏显示连接状态、握手进度、会话安全码与密钥指纹。握手过程不会写入聊天区，避免刷屏。")
body("（2）会话与密码学模块：以 SecureSession 为核心，封装 ECDHE 握手、HKDF 密钥派生、AES-256-GCM 记录层、"
     "消息级密钥棘轮与 DH 棘轮。该模块被客户端与中间人演示工具共同引用，以保证攻击演示与真实通信使用完全相同的协议实现。")
body("（3）中继服务器：只负责按目标 ID 转发密文帧、应答心跳、回收超时连接，不持有任何密钥，属于不可信中继。")

h2("相关功能模块详细设计")
body("ECDHE 密钥交换。双方各自生成一次性 X25519 密钥对，交换公开参数后计算共享秘密 Z = aB = bA。"
     "临时私钥只在本端存在，协商完成后立即销毁，因此会话密钥与任何长期密钥都没有关联。")
body("HKDF 密钥派生与域分离。共享秘密先经 HKDF-Extract 条件化，再按不同 info 标签分别派生出“发起方到响应方”"
     "与“响应方到发起方”两把链密钥以及 Finished 密钥，避免同一密钥双向复用。")
body("AES-256-GCM 记录层。每条消息使用由链密钥派生的消息密钥与随机化 nonce 加密，并把帧头"
     "（版本、类型、会话号、序号、发送方、接收方）作为附加认证数据 AAD。这样服务器一旦修改收发方或重排消息，"
     "接收端在解密时必然失败。")
body("消息级密钥棘轮。每发送一条消息，先由链密钥派生消息密钥与 nonce，再用 HKDF 推进链密钥并覆盖旧值。"
     "因此即使当前链密钥泄露，也无法还原此前消息的密钥。")
body("DH 棘轮（后向恢复）。每发送 8 条消息，发送方生成新的 X25519 密钥对，用旧链加密一条 REKEY 控制帧携带新公钥；"
     "双方随后以 root' = HKDF(salt = root, ikm = DH(新私钥, 对端当前公钥)) 更新根密钥并重建双向链，"
     "发送方旧私钥被覆盖销毁。攻击者即便在某一时刻窃取了棘轮私钥，受害方下一次轮换后也将无法继续推导新密钥。")
body("身份签名与安全码。长期 Ed25519 私钥只用于对握手报文签名，不参与密钥派生。握手完成后双方由 transcript "
     "派生 6 位安全码，并显示在状态栏，供双方口头核对；对端身份公钥首次通信即被固定（TOFU），之后发生变化直接阻断。")
body("中继服务器与心跳。服务器为每个连接维护一把写锁，保证帧不被交错；对帧长度设置上限防止内存耗尽；"
     "每 10 秒巡检一次并回收超过 60 秒无活动的连接，避免崩溃客户端的 ID 被永久占用。")

h2("源代码功能")
body("项目采用分层结构，密码学、协议、服务端、客户端、测试与演示工具相互独立，文件职责如下表所示。")
table(["文件", "职责"], [
    ["Common/crypto_utils.h", "OpenSSL 封装：X25519、HKDF-SHA256、SHA256/HMAC、AES-256-GCM、Ed25519、内存 PEM"],
    ["Common/protocol.h", "协议常量、帧长定义、编解码与 AAD 构造"],
    ["Common/secure_session.h", "可复用安全会话：握手、记录层、消息级棘轮、DH 棘轮、安全码"],
    ["Server/server.cpp", "不可信中继：按 ID 转发、心跳应答、超时回收"],
    ["ClientGUI/ClientGUI.cpp", "Win32 客户端：界面、会话管理、加密持久化、自动重连"],
    ["Tests/crypto_selftest.cpp", "28 项密码学与协议自测"],
    ["Tools/mitm_relay.cpp", "中间人攻击工具（教学演示）"],
    ["Tools/mitm_demo.ps1", "中间人演示与截图自动化"],
    ["Tools/smoke_test.ps1", "端到端功能测试"],
], size=9.5, widths=[5.5, 10])

# ---------------- 三 ----------------
h1("三、关键技术与安全设计")

h2("握手协议与帧格式")
body("握手采用三报文结构，服务器只做原样转发。各报文字段与长度如下表。")
table(["报文", "长度（字节）", "字段构成"], [
    ["INIT", "162", "ver(1) type(1) sid(8) pubA(32) nonceA(16) idpubA(32) idA(4) idB(4) sigA(64)"],
    ["RESP", "186", "ver(1) type(1) sid(8) pubB(32) nonceB(16) idpubB(32) sigB(64) macB(32)"],
    ["CONFIRM", "42", "ver(1) type(1) sid(8) macA(32)"],
    ["REKEY", "66", "ver(1) type(1) sid(8) seq(8) 密文(32) 标签(16)"],
    ["DATA", "18+明文+16", "ver(1) type(1) sid(8) seq(8) 密文 标签(16)"],
], size=9.5, widths=[2.5, 3, 10])
body("其中 sigA 覆盖版本、类型、sid、pubA、nonceA、idpubA 以及双方 ID；sigB 覆盖 RESP 前 90 字节再加上 sigA，"
     "从而把响应绑定到本次请求，防止报文被拼接或跨会话重放。")

h2("密钥调度")
body("握手阶段与记录阶段分别使用不同的 KDF 标签，形成清晰的层次结构：")
code([
    "Z        = X25519(临时私钥, 对端临时公钥)",
    "salt     = nonceA || nonceB",
    "secret   = HKDF-SHA256(Z, salt, \"CHAT-v1 ECDHE X25519\")",
    "chainI2R = HKDF(secret, \"\", \"chain initiator->responder\")",
    "chainR2I = HKDF(secret, \"\", \"chain responder->initiator\")",
    "finished = HKDF(secret, \"\", \"finished key\")",
    "root     = HKDF(secret, \"\", \"root key\")          // DH 棘轮的起点",
])

h2("前向保密的三层论证")
body("（1）握手临时化：每次会话的 X25519 密钥对在首次 DH 轮换后即被销毁，事后无法还原共享秘密。")
body("（2）身份密钥隔离：长期 Ed25519 私钥只负责签名，从不参与密钥派生，因此主密钥泄露不影响历史会话。")
body("（3）棘轮推进：消息密钥随链密钥前进并被覆盖，历史消息密钥不可恢复；DH 棘轮进一步保证被泄露的当前密钥无法用于推导未来密钥。")

# ---------------- 四 ----------------
h1("四、部分核心代码")

h2("SecureSession::Seal（含 DH 棘轮轮换）")
code([
    "if (send_since_rekey_ >= REKEY_INTERVAL) {",
    "    auto fresh = x25519_generate();",
    "    Bytes freshPub = x25519_public_raw(fresh.get());",
    "    // 1) 先用旧链加密 REKEY，对端才能先解密再轮换",
    "    Bytes rec; BuildRecord(proto::REKEY, freshPub, myId, peerId, rec, err);",
    "    out.push_back(rec);",
    "    // 2) Z = DH(新私钥, 对端当前棘轮公钥) → 更新根密钥与双向链",
    "    Bytes z = x25519_shared(fresh.get(), peer.get());",
    "    ApplyRatchet(z, err);",
    "    // 3) 旧私钥被覆盖销毁（后向恢复）",
    "    dh_self_ = std::move(fresh);  send_since_rekey_ = 0;",
    "}",
    "BuildRecord(proto::DATA, body, myId, peerId, rec, err);",
    "out.push_back(rec); send_since_rekey_++;",
])

h2("SecureSession::Open 中的 REKEY 处理")
code([
    "bool ok = aead_decrypt(msg_key, nonce, ct, aad, plain);   // aad 含 type/sid/seq/收发方",
    "recv_chain_ = next;  recv_seq_++;",
    "if (type == proto::REKEY) {",
    "    Bytes newPeerPub(plain.begin(), plain.end());",
    "    Bytes z = x25519_shared(dh_self_.get(), peer.get());",
    "    ApplyRatchet(z, err);          // 重建根密钥与双向链",
    "    dh_peer_pub_ = newPeerPub;",
    "    isControl = true; return true; // 控制帧，不展示给用户",
    "}",
])

h2("服务器转发（防帧交错与内存耗尽）")
code([
    "if (len < 4 || len > proto::MAX_PAYLOAD) break;       // 防止长度字段导致 OOM",
    "SessionPtr dst; { lock(g_clients_mu); dst = find(target); }  // 锁内只查找",
    "if (dst) {",
    "    std::lock_guard<std::mutex> lk(dst->write_mu);    // 每连接一把写锁",
    "    write(dst->sock, &len, 4); write(dst->sock, payload, len);",
    "}",
])

# ---------------- 五 ----------------
h1("五、软件测试及其结果分析")

h2("密码学与协议自测")
body("编写了 28 项自动化断言，覆盖签名、密钥交换、KDF、AEAD、棘轮与完整协议流程，全部通过。摘要如下表。")
table(["测试组", "主要断言", "结果"], [
    ["Ed25519", "正确签名通过；篡改消息失败；冒用公钥失败；PEM 存取一致", "通过"],
    ["X25519", "双方共享秘密一致；长度 32 字节；两次握手共享秘密不同", "通过"],
    ["HKDF", "发送链等于对端接收链；方向密钥独立；不同标签派生不同密钥", "通过"],
    ["AES-GCM", "正确解密；篡改 AAD、篡改密文、错误密钥均失败", "通过"],
    ["消息棘轮", "连续 8 条同步；当前链密钥无法恢复历史消息密钥", "通过"],
    ["DH 棘轮", "完整握手 + 20 条消息（含 2 次自动轮换）后仍同步；反向消息可解", "通过"],
], size=9.5, widths=[3, 11, 2])

h2("端到端功能测试")
body("脚本自动启动服务器与两个客户端，驱动界面互发消息，并通过解密导出校验送达情况。实测输出如下：")
code([
    "[OK] client 2 decrypted message 1",
    "[OK] client 1 decrypted message 2",
    "[OK] outgoing message persisted",
    "[OK] DH ratchet: 10 messages delivered after rekey",
    "[OK] chat log encrypted at rest",
])
body("服务器日志同时给出了协议交互的完整证据，从中可以看出服务器全程只能看到密文与长度：")
code([
    "[中继] 1 -> 2 转发 162 字节（内容不可解密）   <- HS_INIT",
    "[中继] 2 -> 1 转发 186 字节（内容不可解密）   <- HS_RESP",
    "[中继] 1 -> 2 转发 42  字节（内容不可解密）   <- HS_CONFIRM",
    "[中继] 1 -> 2 转发 53  字节（内容不可解密）   <- 加密消息",
])

h2("中间人攻击实验")
body("为定量验证安全边界，额外实现了一个中间人工具：它冒充中继服务器，对每一对通信者分别与两端各完成一次握手，"
     "从而同时握有两把会话密钥，可在双方界面均显示“会话已建立”的情况下解密并转发消息。实测结果如下：")
code([
    "[MITM] 已冒充用户 2 接受用户 1 的握手",
    "[MITM] 已冒充用户 1 向用户 2 发起握手",
    "[MITM] 欺骗成功：用户 1 与用户 2 都显示“加密会话已建立”",
    "[MITM] 但两端的安全码不同：用户 1 看到 629420，用户 2 看到 795209",
    "[截获] 1 -> 2 明文: card-password-is-123456",
    "[抓包]   密文 39 字节，前 16 字节 fdb3776657d7af05ca5e9bc670fd210e",
])
picture(IMG1, 12.5)
caption("图 2 客户端显示“会话已建立”与安全码（被劫持时两端安全码不同）")
picture(IMG2, 12.5)
caption("图 3 另一端客户端看到的另一个安全码")
body("实验结论：在“首次接触且中间人在场”的情况下，仅靠 ECDHE 与自我介绍式身份公钥无法阻止中间人，这是信息论"
     "限制而非实现缺陷；但两端安全码必然不同，只要双方核对一次即可发现劫持。这与 Signal、WhatsApp 的安全模型一致。")

h2("前向保密与本地数据保护验证")
body("（1）会话密钥独立性：连续两次握手，抓包得到的公钥与密文均不相同。")
body("（2）主密钥泄露：记录密文后删除 identity.pem 并重启，历史密文依然无法解密。")
body("（3）后向恢复：连续发送超过 8 条消息后触发 DH 轮换，抓包可见 REKEY 帧，且轮换前后密文无法互相解密。")
body("（4）本地保护：identity.pem 为 DPAPI 密文（文件头为 01 00 00 00 d0 8c 9d df…），聊天记录为 hex 密文，"
     "直接搜索明文不可见；使用 --dump 参数可解密导出，用于备份与测试校验。")

# ---------------- 六 ----------------
h1("六、课题完成过程中遇到的问题及解决方法")

body("（1）问题1：最初的实现中任何客户端都能解出别人的消息。", indent=0)
body("解决方法：审查发送路径发现会话密钥被直接取为“32 字节的用户 ID”，而 ID 是服务器分配并公开显示的，"
     "等于密钥公开；同时 crypto_utils.h 中的 X25519 函数是从未被调用的死代码。于是重写为完整的 ECDHE 握手，"
     "密钥只由临时私钥派生，并在会话建立后销毁临时私钥。教训是“调用了加密库”并不等于“实现了加密”。")

body("（2）问题2：握手两端都显示成功，但对方始终收不到消息。", indent=0)
body("解决方法：服务器日志中只出现 INIT 与 RESP，从未出现 CONFIRM，说明发起方在校验 RESP 时返回了。"
     "对比签名与验签的输入发现：响应方签的是“RESP 前 90 字节 + sigA”，而发起方验签时把已包含 sigB 的 154 字节"
     "又拼上 sigA 当作被签数据，实际验签 218 字节，必然失败。改为统一使用 HS_RESP_BASE 切片构造签名输入。")

body("（3）问题3：客户端启动即弹出“OpenSSL: FATAL”对话框。", indent=0)
body("解决方法：控制台版本复现后报出了明确的 OPENSSL_Uplink: no OPENSSL_Applink。根因是 vcpkg 提供的是 OpenSSL "
     "静态库，Windows 下静态链接时使用 PEM_read_PrivateKey(FILE*) 这类基于 FILE* 的接口需要 applink 跳转表。"
     "改为自行以 fread/fwrite 读写文件，PEM 编解码走内存 BIO，彻底绕开 FILE* 接口。")

body("（4）问题4：身份与聊天记录文件始终写不进去，每次重启身份指纹都变。", indent=0)
body("解决方法：%APPDATA% 路径含中文用户名，而代码用 ANSI 版的 fopen_s 打开，在 GBK 代码页下无法表示该路径且"
     "静默失败。所有文件操作统一改为宽字符路径与 _wfopen_s。")

body("（5）问题5：给不在线的用户发消息，界面毫无反应。", indent=0)
body("解决方法：服务器发送系统提示时组帧漏掉了 4 字节的发送者前缀，客户端按“长度 + 发送者 + 载荷”解析时"
     "取到的类型字段并不是 SYSTEM，消息被静默丢弃。新增统一的 SendPayload 组帧函数，系统消息使用发送者 -1。")

body("（6）问题6：DH 棘轮上线后，第 8 条消息开始全部丢失。", indent=0)
body("解决方法：单元测试（20 条消息含 2 次轮换）全部通过，说明算法正确；对比真实链路后发现问题出在分发层——"
     "客户端与中间人工具的 switch 只处理了 DATA，新增的 REKEY 帧被 default 分支丢弃，接收方序号少一，导致后续全部失步。"
     "在所有分发点补上 REKEY 分支后恢复正常。")

body("（7）问题7：根密钥实际上是用已清零的缓冲区派生的。", indent=0)
body("解决方法：代码审查时发现 root_key_ 的派生写在了 crypto::wipe(secret) 之后。wipe 只清零内容不改变长度，"
     "因此 HKDF 仍能成功返回 32 字节，但输入已全为 0，双方行为一致所以“功能正常”，安全性却归零。"
     "将派生移回擦除之前，并加注释强调顺序。")

body("（8）问题8：自动化测试出现“假成功”。", indent=0)
body("解决方法：两个原因叠加——跨进程读取多行 EDIT 控件不可靠总是返回空；断言用的正则又匹配到了发送方自己的回显行。"
     "改为让客户端支持 --dump 导出解密后的历史，断言针对导出文件并加上行首锚点，同时故意破坏代码确认断言会变红。")

# ---------------- 七 ----------------
h1("七、总结")
body("本次课程设计围绕“基于 ECDHE 的前向保密聊天工具”展开。通过查阅资料，明确了前向保密的本质是“把长期密钥"
     "与一次性会话密钥解耦”，从而在长期密钥泄露时保护历史通信；也理解了 ECDHE 只是实现手段，前向保密才是需要证明的安全属性。")
body("具体实现上，系统采用 C++17 与 OpenSSL 3.x，自行实现了 TLS 1.3 风格的握手：X25519 临时密钥交换、"
     "HKDF-SHA256 域分离派生、AES-256-GCM 记录层与 Ed25519 身份签名。在此之上叠加了消息级密钥棘轮与周期性 DH 棘轮，"
     "同时获得前向保密与后向恢复能力。中继服务器被设计为不可信中继，任何时刻都不持有密钥。")
body("为了让安全属性可验证，除功能测试外还实现了中间人攻击工具、端到端自动化测试与 28 项密码学断言。"
     "中间人实验给出的结论是诚实的：首次接触时中间人确实可以完成劫持，但会暴露为两端安全码不一致；"
     "这也正是 Signal、WhatsApp 要求用户核对安全码的原因。")
body("系统仍有明确的边界：未实现离线消息、群聊与文件传输，未做消息分片，元数据（通信关系、消息长度）对服务器"
     "仍然可见，身份信任仍依赖人工核对而非 PKI。后续可通过双棘轮逐消息头、KeyUpdate、消息填充与形式化验证"
     "（ProVerif/Tamarin）继续完善。")
body("通过本次设计，我不仅掌握了 ECDHE、HKDF、AEAD 与数字签名的具体用法，更重要的是建立了“先建模威胁、"
     "再选择机制、最后用实验证伪”的安全工程思维。")

# ---------------- 附录 ----------------
h1("附录 A 运行与演示命令")
code([
    "构建：",
    "  cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake",
    "  cmake --build build --config Debug",
    "运行：",
    "  build\\Debug\\Server_App.exe",
    "  build\\Debug\\ClientGUI_App.exe --profile alice",
    "  build\\Debug\\ClientGUI_App.exe --profile bob",
    "测试：",
    "  build\\Debug\\CryptoTest.exe",
    "  powershell -File Tools\\smoke_test.ps1",
    "  powershell -File Tools\\mitm_demo.ps1",
    "导出聊天记录（解密）：",
    "  build\\Debug\\ClientGUI_App.exe --profile alice --dump D:\\backup\\alice.txt",
])

os.makedirs(OUTDIR, exist_ok=True)
doc.save(OUT)
print("saved:", OUT)
print("exists:", os.path.exists(OUT), os.path.getsize(OUT) if os.path.exists(OUT) else 0)
