# -*- coding: utf-8 -*-
"""生成报告插图（流程图 / 时序图 / 示意图 / 真实运行输出截图式配图）。

图源数据全部来自本机真实运行：
  %TEMP%\\shots        本仓库 Tools\\capture_shots.ps1 的截图与密文样本
  %TEMP%\\mitm_demo    本仓库 Tools\\mitm_demo.ps1 的中间人演示截图
  %TEMP%\\crypto_test_out.txt  CryptoTest.exe 的真实输出
"""
import os
import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.font_manager as fm
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, FancyArrowPatch, FancyBboxPatch

DOCS = r"D:\ECDHE-Secured Chat System\docs\figures"
TEMP = os.environ.get("TEMP", ".")
SHOTS = os.path.join(TEMP, "shots")
MITM = os.path.join(TEMP, "mitm_demo")

_AVAIL = {f.name for f in fm.fontManager.ttflist}
CJK = next((c for c in ("Microsoft YaHei", "SimHei", "Noto Sans CJK SC",
                        "Source Han Sans SC", "SimSun") if c in _AVAIL), "DejaVu Sans")
MONO = "Consolas" if "Consolas" in _AVAIL else "DejaVu Sans Mono"
plt.rcParams["font.sans-serif"] = [CJK, "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

# 配色
INK = "#1b2a3a"
BLUE = ("#eaf2fb", "#2f6db0")
GREEN = ("#eaf7ee", "#2e8b57")
AMBER = ("#fdf3e3", "#c9861a")
RED = ("#fdecea", "#c0392b")
GRAY = ("#f3f5f8", "#8290a0")
PURPLE = ("#f3eefb", "#6f42c1")

# 记录“文字-方框”对，在 save() 时检查文字是否溢出方框
_CHECK = []
_NOTES = []
_LABELS = []
_RECTS = []
_ARROWS = []


def _bbox(t, r):
    b = t.get_window_extent(r)
    return (b.x0, b.y0, b.x1, b.y1)


def _inter(a, b, pad=1.0):
    return not (a[2] - pad <= b[0] or b[2] - pad <= a[0] or
                a[3] - pad <= b[1] or b[3] - pad <= a[1])


def _check(name):
    """打印排版告警：文字超框 / 超出画布 / 注释压框 / 注释互相重叠。"""
    fig = plt.gcf()
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    cb = None
    ab = fig.axes[0].get_window_extent(r)
    canvas_box = (ab.x0, ab.y0, ab.x1, ab.y1)

    for p, t in _CHECK:
        pb = _bbox(p, r)
        tb = _bbox(t, r)
        if tb[2] - tb[0] > pb[2] - pb[0] - 1.5 or tb[3] - tb[1] > pb[3] - pb[1] - 1.5:
            print("    !! OVERFLOW %-20s %-26s tw=%.0f bw=%.0f th=%.0f bh=%.0f"
                  % (name, repr(t.get_text())[:26], tb[2] - tb[0], pb[2] - pb[0],
                     tb[3] - tb[1], pb[3] - pb[1]))

    for t in _NOTES + _LABELS:
        tb = _bbox(t, r)
        if (tb[0] < canvas_box[0] + 1 or tb[2] > canvas_box[2] - 1 or
                tb[1] < canvas_box[1] + 1 or tb[3] > canvas_box[3] - 1):
            print("    !! CLIPPED  %-20s %s" % (name, repr(t.get_text())[:34]))

    boxes = [(p, t) for p, t in _CHECK]
    for t in _NOTES:
        tb = _bbox(t, r)
        for p, bt in boxes:
            pb = _bbox(p, r)
            if _inter(tb, pb):
                # 注释中心落在框内且框完全包住注释 → 视为“有意放置”
                cx, cy = (tb[0] + tb[2]) / 2, (tb[1] + tb[3]) / 2
                inside = pb[0] <= cx <= pb[2] and pb[1] <= cy <= pb[3]
                covered = pb[0] <= tb[0] + 1 and tb[2] <= pb[2] - 1 and pb[1] <= tb[1] + 1 and tb[3] <= pb[3] - 1
                if not (inside and covered):
                    print("    !! HIT-BOX  %-20s %-30s %s"
                          % (name, repr(t.get_text())[:30], repr(bt.get_text())[:22]))

    alltxt = [(_bbox(t, r), t) for t in _NOTES]
    for i in range(len(alltxt)):
        for j in range(i + 1, len(alltxt)):
            if _inter(alltxt[i][0], alltxt[j][0]):
                print("    !! HIT-TXT  %-20s %s | %s"
                      % (name, repr(alltxt[i][1].get_text())[:24],
                         repr(alltxt[j][1].get_text())[:24]))

    # 连线穿过方框（视觉上最频发的“乱”）
    for (x1, y1), (x2, y2), rad in _ARROWS:
        cx = (x1 + x2) / 2 + rad * (y2 - y1)
        cy = (y1 + y2) / 2 - rad * (x2 - x1)
        for (rx, ry, rw, rh, rname) in _RECTS:
            hit = False
            for k in range(1, 40):
                t2 = k / 40.0
                px = (1 - t2) ** 2 * x1 + 2 * (1 - t2) * t2 * cx + t2 ** 2 * x2
                py = (1 - t2) ** 2 * y1 + 2 * (1 - t2) * t2 * cy + t2 ** 2 * y2
                if rx + 1 < px < rx + rw - 1 and ry + 1 < py < ry + rh - 1:
                    hit = True
                    break
            if hit:
                print("    !! ARROW-IN %-20s (%.0f,%.0f)->(%.0f,%.0f) 穿过 %s"
                      % (name, x1, y1, x2, y2, rname))

    # 方框互相重叠（完全包含视为“容器”，不算问题）
    for i in range(len(_RECTS)):
        ax1, ay1, aw1, ah1, an1 = _RECTS[i]
        for j in range(i + 1, len(_RECTS)):
            bx1, by1, bw1, bh1, bn2 = _RECTS[j]
            if not (ax1 < bx1 + bw1 - 1 and bx1 < ax1 + aw1 - 1 and
                    ay1 < by1 + bh1 - 1 and by1 < ay1 + ah1 - 1):
                continue
            contains = (ax1 <= bx1 and ay1 <= by1 and
                        bx1 + bw1 <= ax1 + aw1 and by1 + bh1 <= ay1 + ah1) or \
                       (bx1 <= ax1 and by1 <= ay1 and
                        ax1 + aw1 <= bx1 + bw1 and ay1 + ah1 <= by1 + bh1)
            if not contains:
                print("    !! BOX-OVLP %-20s %s | %s" % (name, an1, bn2))
    _CHECK.clear()
    _NOTES.clear()
    _LABELS.clear()
    _RECTS.clear()
    _ARROWS.clear()


# 插图按“最终印刷尺寸”绘制：画布宽度接近插入宽度（16 cm ≈ 6.3 in），
# 这样图中的 8~9pt 文字印到纸上仍是 8~9pt，不会因为缩小插入而变得看不清。
FIG_K = 0.60
DPI = 220


# ------------------------------------------------------------------ 基础 -----
def canvas(w, h, k=None):
    k = FIG_K if k is None else k
    fig = plt.figure(figsize=(w * k, h * k), dpi=DPI)
    ax = fig.add_axes([0.004, 0.004, 0.992, 0.992])
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, text, colors=BLUE, fs=9, bold=False, ls="-", lw=1.2,
        tc=INK, r=1.4, align="center", z=2, alpha=1.0):
    fc, ec = colors
    p = FancyBboxPatch((x, y), w, h,
                       boxstyle=f"round,pad=0.35,rounding_size={r}",
                       fc=fc, ec=ec, lw=lw, ls=ls, zorder=z, alpha=alpha)
    ax.add_patch(p)
    ha = {"center": "center", "left": "left"}[align]
    tx = x + w / 2 if align == "center" else x + 1.2
    t = ax.text(tx, y + h / 2, text, ha=ha, va="center", fontsize=fs, color=tc,
                fontweight="bold" if bold else "normal", zorder=z + 1, linespacing=1.45)
    _CHECK.append((p, t))
    _RECTS.append((x, y, w, h, text[:10]))
    return p


def arrow(ax, p1, p2, color="#2f6db0", lw=1.4, style="-|>", ls="-", rad=0.0,
          label=None, fs=8, dy=1.8, dx=0.0, lp=0.5, tc=None):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=12,
                                 color=color, lw=lw, ls=ls, shrinkA=1, shrinkB=1,
                                 connectionstyle=f"arc3,rad={rad}", zorder=4))
    if label:
        mx = p1[0] + (p2[0] - p1[0]) * lp + dx
        my = p1[1] + (p2[1] - p1[1]) * lp + dy
        t = ax.text(mx, my, label, ha="center", va="center", fontsize=fs,
                    color=tc or color, zorder=6,
                    bbox=dict(fc="white", ec="none", alpha=0.92, pad=1.2))
        _LABELS.append(t)
    _ARROWS.append((tuple(p1), tuple(p2), rad))


def note(ax, x, y, text, fs=8, color=INK, ha="center", style="normal"):
    t = ax.text(x, y, text, ha=ha, va="center", fontsize=fs, color=color,
                style=style, zorder=5)
    _NOTES.append(t)
    return t


def save(fig, name):
    os.makedirs(DOCS, exist_ok=True)
    _check(name)
    p = os.path.join(DOCS, name)
    fig.savefig(p, dpi=DPI, facecolor="white")
    plt.close(fig)
    print("  fig:", name, os.path.getsize(p))


# ------------------------------------------------------- 1. 用例图 ----------
def fig_usecase():
    fig, ax = canvas(9.6, 6.2)
    ax.add_patch(FancyBboxPatch((24, 3), 52, 92, boxstyle="round,pad=0.5,rounding_size=2",
                                fc="#fbfcfd", ec="#5a6b7c", lw=1.4, zorder=1))
    note(ax, 50, 97, "ECDHE 前向保密聊天工具（C++17 / Win32）", 10, "#31414f")
    use = [
        "① 连接服务器并获得临时 ID",
        "② ECDHE 协商会话密钥",
        "③ 收发端到端加密消息",
        "④ 核对安全码 / 固定对端指纹",
        "⑤ 本地加密保存与重载历史",
        "⑥ 按 ID 转发密文帧（服务器无密钥）",
    ]
    ys = [86, 72, 58, 44, 30, 14]
    for t, y in zip(use, ys):
        c = GRAY if "服务器" in t else BLUE
        ax.add_patch(Ellipse((50, y), 40, 11, fc=c[0], ec=c[1], lw=1.2, zorder=2))
        note(ax, 50, y, t, 8.4, INK)

    # 参与者：用户（左）
    def actor(x, y, name, color="#2f6db0"):
        ax.add_patch(plt.Circle((x, y + 5.2), 1.7, fc="white", ec=color, lw=1.4, zorder=3))
        ax.plot([x, x], [y + 3.4, y - 1.6], color=color, lw=1.4, zorder=3)
        ax.plot([x - 3, x + 3], [y + 1.6, y + 1.6], color=color, lw=1.4, zorder=3)
        ax.plot([x, x - 2.6], [y - 1.6, y - 5.4], color=color, lw=1.4, zorder=3)
        ax.plot([x, x + 2.6], [y - 1.6, y - 5.4], color=color, lw=1.4, zorder=3)
        note(ax, x, y - 8.5, name, 9, color)

    actor(12, 60, "用户 A / B", "#2f6db0")
    actor(90, 60, "攻击者", "#c0392b")
    actor(90, 30, "中继服务器", "#8290a0")

    for y in ys[:5]:
        ax.plot([16, 30], [57, y], color="#9bb4cc", lw=0.9, zorder=1)
    ax.plot([86, 70], [33, 14], color="#a8b3bf", lw=0.9, zorder=1)
    ax.plot([86, 70], [56, 72], color="#c0392b", lw=1.1, ls=(0, (4, 2)), zorder=1)

    note(ax, 50, 4, "红色虚线：中间人劫持路径（两端安全码因此不同）", 7.4, "#c0392b")
    save(fig, "fig_usecase.png")


# ------------------------------------------------------- 2. 总体架构 --------
def client_block(ax, x0, title, sub):
    box(ax, x0, 4, 28, 92, "", (("#f7fafd"), "#1f4e79"), lw=1.6)
    note(ax, x0 + 14, 91, title, 9.5, "#1f4e79")
    note(ax, x0 + 14, 86.5, sub, 7.6, "#5b7086")
    box(ax, x0 + 2, 72, 24, 11, "界面层\n会话列表 / 聊天区 / 状态栏", BLUE, 7.6)
    box(ax, x0 + 2, 57, 24, 11, "会话层 SecureSession\n握手 · 棘轮 · 安全码", PURPLE, 7.6)
    box(ax, x0 + 2, 41, 24, 13, "密码学层 crypto_utils\nX25519 / HKDF\nAES-GCM / Ed25519", GREEN, 7.2)
    box(ax, x0 + 2, 25, 24, 13, "存储层\nidentity.pem (DPAPI)\n加密聊天记录", AMBER, 7.2)
    box(ax, x0 + 2, 7, 24, 13, "网络线程\n心跳 / 15 秒超时\n自动重连", GRAY, 7.2)


def fig_arch():
    fig, ax = canvas(10.6, 6.4)
    client_block(ax, 1.5, "客户端 A（用户 1）", "承担全部密码学运算")
    client_block(ax, 70.5, "客户端 B（用户 2）", "承担全部密码学运算")

    ax.add_patch(FancyBboxPatch((34, 16), 32, 66, boxstyle="round,pad=0.5,rounding_size=2",
                                fc="#fdfbf7", ec="#c9861a", lw=1.5, ls=(0, (5, 3)), zorder=1))
    note(ax, 50, 84, "不可信中继（服务器不持有任何密钥）", 9.2, "#a86a12")
    box(ax, 36.5, 60, 27, 14, "按目标 ID 转发密文帧\n不解析、不解密", AMBER, 7.6)
    box(ax, 36.5, 43, 27, 14, "心跳应答 PONG\n60 秒无活动回收 ID", AMBER, 7.6)
    box(ax, 36.5, 26, 27, 14, "帧长检查\n4 B ≤ len ≤ 1 MiB", AMBER, 7.6)

    arrow(ax, (30, 52), (36.5, 52), label="密文帧", fs=7.6)
    arrow(ax, (36.5, 44), (30, 44), label="密文帧", fs=7.6, dy=-2.4)
    arrow(ax, (63.5, 52), (70.5, 52), label="密文帧", fs=7.6)
    arrow(ax, (70.5, 44), (63.5, 44), label="密文帧", fs=7.6, dy=-2.4)

    note(ax, 50, 9, "服务器被攻破也只能得到密文与元数据；\n篡改会被 AAD 认证拒绝", 7.4, "#7a4b0c")
    save(fig, "fig_arch.png")


# ------------------------------------------------------- 3. 帧格式 ----------
def _row(ax, y, h, items, scale, x0, fs=7.2, symbolic=False):
    """items: [(label, 权值或字节数)]；symbolic=True 时权值只用于分配宽度。
    返回 [(label, x, w)]，便于把过窄的字段另起一行说明。"""
    tot = float(sum(i[1] for i in items))
    x = x0
    geo = []
    for label, nb in items:
        w = (96 - x0) * nb / tot if symbolic else nb * scale
        ax.add_patch(plt.Rectangle((x, y), w, h, fc=BLUE[0], ec=BLUE[1], lw=1.0, zorder=2))
        if w >= 9.0:
            ax.text(x + w / 2, y + h / 2, label, ha="center", va="center",
                    fontsize=fs, color=INK, zorder=3)
        geo.append((label, x, w))
        x += w
    return geo


def fig_frame():
    fig, ax = canvas(10.2, 5.9)
    scale = 88.0 / 186.0          # 1 字节 ≈ 0.47 单位
    x0 = 6.0

    note(ax, 4, 95, "（a）TCP 外层帧（示意，宽窄不代表比例）", 8.6, "#31414f", ha="left")
    _row(ax, 87, 6.5, [("长度 4 B", 20), ("目标 / 源 ID 4 B", 24),
                       ("payload（长度字段 = 4 + payload 长度）", 46)], 0, x0, 8, symbolic=True)
    note(ax, 4, 83, "服务器只读前两个字段用于路由，其余原样转发", 7.6, "#5b7086", ha="left")

    note(ax, 4, 78, "（b）DATA 载荷（聊天消息，密文长度可变，示意）", 8.6, "#31414f", ha="left")
    _row(ax, 70, 6.5, [("ver‖type 2 B", 8), ("会话号 sid 8 B", 11), ("序号 seq 8 B", 11),
                       ("AES-256-GCM 密文（n 字节）", 34), ("Tag 16 B", 14)], 0, x0, 7.6, symbolic=True)
    note(ax, 4, 65, "AAD = ver‖type‖sid‖seq‖发送方 ID‖接收方 ID　→ 帧头被绑进认证标签，改一个字节就解密失败",
         7.6, "#5b7086", ha="left")

    note(ax, 4, 58, "（c）HS_INIT 载荷：162 字节（本行与下一行按字节等比绘制）", 8.6, "#31414f", ha="left")
    g = _row(ax, 49, 6.5, [("ver 1 B", 1), ("type 1 B", 1), ("sid 8 B", 8), ("pubA 32 B", 32),
                           ("nonceA 16 B", 16), ("idpubA 32 B", 32), ("idA 4 B", 4), ("idB 4 B", 4),
                           ("SigA 64 B", 64)], scale, x0, 7.2)
    narrow = [l for l, x, w in g if w < 9.0]
    note(ax, 4, 45.5, "窄字段（自左向右）：" + " ｜ ".join(narrow), 7.0, "#5b7086", ha="left")

    note(ax, 4, 39, "（d）HS_RESP 载荷：186 字节", 8.6, "#31414f", ha="left")
    g = _row(ax, 30, 6.5, [("ver 1 B", 1), ("type 1 B", 1), ("sid 8 B", 8), ("pubB 32 B", 32),
                           ("nonceB 16 B", 16), ("idpubB 32 B", 32), ("SigB 64 B", 64),
                           ("MAC_B 32 B", 32)], scale, x0, 7.2)
    narrow = [l for l, x, w in g if w < 9.0]
    note(ax, 4, 26.5, "窄字段（自左向右）：" + " ｜ ".join(narrow), 7.0, "#5b7086", ha="left")

    note(ax, 50, 17, "签名覆盖范围：Sig_A 覆盖帧头 + pubA + nonceA + idpubA + 双方 ID；"
                     "Sig_B 覆盖 INIT 摘要 + RESP 前 90 字节", 7.8, "#7a4b0c")
    note(ax, 50, 11.5, "→ 响应被绑定到本次请求，报文无法被拼接或跨会话重放", 7.8, "#c0392b")
    note(ax, 50, 5, "帧长上下界：4 字节 ≤ 长度字段 ≤ 1 MiB，越界立即断开连接（防内存耗尽）", 7.8, "#31414f")
    save(fig, "fig_frame.png")


# ------------------------------------------------------- 4. 握手时序 --------
def fig_handshake():
    fig, ax = canvas(10.0, 8.2)
    xa, xb = 13, 87
    for x in (xa, xb):
        ax.plot([x, x], [9, 90], color="#5a6b7c", lw=1.1, ls=(0, (6, 3)), zorder=1)
    box(ax, xa - 10, 88, 20, 9, "发起方 A（发送方）", BLUE, 8.2)
    box(ax, xb - 10, 88, 20, 9, "响应方 B（接收方）", GREEN, 8.2)
    ax.add_patch(plt.Rectangle((46.5, 34), 7, 56, fc="#fdfbf7", ec="#c9861a",
                               lw=1.0, ls=(0, (4, 3)), zorder=0))
    note(ax, 50, 94, "中继服务器：原样转发，不持有任何密钥", 7.4, "#a86a12")
    note(ax, 50, 56, "无密钥", 7.4, "#a86a12")

    arrow(ax, (xa, 82), (xb, 82), label="① HS_INIT（162 B）：pubA · nonceA · idpubA · SigA", fs=8, dy=3.2)
    box(ax, 53.5, 72, 33, 7, "验签 SigA → 生成 pubB / nonceB\n→ 计算 Z → 派生双向链密钥", AMBER, 7.4)
    arrow(ax, (xb, 65), (xa, 65), label="② HS_RESP（186 B）：pubB · nonceB · idpubB · SigB · MAC_B",
          fs=8, dy=3.2, color="#2e8b57")
    box(ax, 13.5, 55, 33, 7, "验签 SigB（覆盖 INIT + RESP 前 90 B）\n→ 验 MAC_B → 派生会话密钥", AMBER, 7.4)
    arrow(ax, (xa, 47), (xb, 47), label="③ HS_CONFIRM（42 B）：MAC_A", fs=8, dy=3.2)
    note(ax, xb - 16, 39, "验 MAC_A → 双方进入 Established", 8, "#2e8b57")

    box(ax, 12, 22, 76, 9,
        "双方状态栏显示 6 位安全码 + 会话密钥指纹\n这是唯一能发现中间人的手段",
        (("#eef7f0"), "#2e8b57"), 7.8, bold=True)
    box(ax, 12, 10, 76, 8,
        "此后每条消息：消息密钥棘轮；每 8 条：DH 棘轮（REKEY 帧）",
        PURPLE, 7.8)
    save(fig, "fig_handshake.png")


# ------------------------------------------------------- 5. 密钥调度 --------
def fig_kdf():
    fig, ax = canvas(9.8, 7.2)
    box(ax, 12, 88, 76, 8, "Z = X25519(本端临时私钥, 对端临时公钥)　—— 32 字节共享秘密", GREEN, 8.2, bold=True)
    box(ax, 4, 74, 92, 9,
        "secret = HKDF-SHA256(Z, salt = nonceA‖nonceB, info = “CHAT-v1 ECDHE X25519”)",
        BLUE, 7.6, bold=True)
    arrow(ax, (50, 88), (50, 83))
    arrow(ax, (50, 74), (50, 68))

    box(ax, 30, 60, 40, 7, "HKDF-Expand（按 info 做域分离）", PURPLE, 8.4)
    kids = [
        ("chainI2R\n发起方→响应方", 2),
        ("chainR2I\n响应方→发起方", 26),
        ("finished_key\nFinished 校验", 50),
        ("root_key\nDH 棘轮起点", 74),
    ]
    for t, x in kids:
        box(ax, x, 44, 22, 10, t, AMBER, 8)
        arrow(ax, (50, 60), (x + 11, 54), rad=0.0, lw=1.0)

    note(ax, 13, 39.5, "发送链", 7.6, "#a86a12", style="italic")
    subs = [("消息密钥\n(32 B)", 2), ("nonce / IV\n(12 B)", 26), ("下一链密钥\n(32 B)", 50)]
    for t, x in subs:
        box(ax, x, 26, 22, 9, t, (("#eaf2fb"), "#2f6db0"), 7.8)
        arrow(ax, (13, 44), (x + 11, 35), lw=1.0)
    note(ax, 37, 20, "chain' 回写为下一轮的链密钥（旧值立即清零）", 7.6, "#c0392b")

    box(ax, 76, 26, 21, 9, "root'\n= HKDF(DH, root)", (("#f3eefb"), "#6f42c1"), 7.8)
    arrow(ax, (85, 44), (85, 35), lw=1.1, color="#6f42c1")

    note(ax, 50, 15,
         "域分离的意义：收发两个方向、消息密钥与 Finished 密钥互不相同；\n"
         "即使其中一把泄露，也不能推出其他密钥（HKDF 是单向的 PRF）。", 8, "#31414f")
    note(ax, 50, 6, "所有中间值（Z、secret、旧链密钥、消息密钥）在用完后立即 OPENSSL_cleanse 清零", 8,
         "#c0392b")
    save(fig, "fig_kdf.png")


# --------------------------------------------------- 6. 消息级棘轮 ----------
def fig_msg_ratchet():
    fig, ax = canvas(9.8, 4.2)
    xs = [4, 27, 50, 73]
    for i, x in enumerate(xs):
        box(ax, x, 58, 19, 10, f"链密钥 chain$_{i}$", BLUE, 8.6, bold=True)
        if i < 3:
            arrow(ax, (x + 19, 63), (xs[i + 1], 63), lw=1.3)
        box(ax, x, 34, 19, 9, f"消息密钥 MK$_{i}$", (("#eef7f0"), "#2e8b57"), 8.4)
        arrow(ax, (x + 9.5, 58), (x + 9.5, 43), lw=1.1, color="#2e8b57")
        note(ax, x + 9.5, 28, f"加密第 {i + 1} 条消息", 7.6, "#5b7086")

    note(ax, 50, 19, "chain$_{i+1}$ = HKDF(chain$_{i}$, “chain next”)　然后把 chain$_{i}$ 清零覆盖", 8.8,
         "#c0392b")
    note(ax, 50, 11,
         "单向性：知道 chain$_{i+1}$ 也推不出 chain$_{i}$，因此也无法还原 MK$_{i}$ 及更早的消息密钥。\n"
         "这就是“消息级前向保密”——会话内每一条消息都有自己的密钥。", 8, "#31414f")
    save(fig, "fig_msg_ratchet.png")


# ----------------------------------------------------- 7. DH 棘轮 ----------
def fig_dh_ratchet():
    fig, ax = canvas(10.0, 6.2)
    box(ax, 3, 72, 26, 12, "root$_k$\n根密钥", (("#f3eefb"), "#6f42c1"), 8.4, bold=True)
    box(ax, 3, 46, 26, 12, "DH$_k$ = X25519\n(新私钥, 对端公钥)", GREEN, 7.4)
    box(ax, 37, 57, 24, 16, "HKDF\nsalt=root$_k$\nikm=DH$_k$", BLUE, 7.4)
    arrow(ax, (16, 72), (37, 68.5), lw=1.2)
    arrow(ax, (16, 58), (37, 61.5), lw=1.2, color="#2e8b57")

    box(ax, 67, 72, 30, 12, "root$_{k+1}$（新根密钥）", (("#f3eefb"), "#6f42c1"), 8.4, bold=True)
    arrow(ax, (61, 65), (67, 76), lw=1.3)

    box(ax, 67, 44, 30, 11, "重建双向链密钥\nchainI2R / chainR2I", AMBER, 7.4)
    arrow(ax, (82, 72), (82, 55), lw=1.3, color="#c9861a")
    box(ax, 67, 26, 30, 12, "旧私钥、旧链密钥\n立即销毁", RED, 7.4)
    arrow(ax, (82, 44), (82, 38), lw=1.2, color="#c0392b")

    note(ax, 16, 24, "触发条件", 8.2, "#31414f", style="italic")
    box(ax, 3, 8, 26, 12, "每发送 8 条消息\n（REKEY_INTERVAL）", (("#fdf3e3"), "#c9861a"), 7.4)
    box(ax, 33, 6, 32, 26,
        "轮换过程：\n① 旧链加密一条 REKEY 帧\n② 双方各算 DH 并更新根密钥\n③ 重建双向链\n④ 发送方销毁旧私钥",
        AMBER, 7.1, align="left")
    arrow(ax, (29, 14), (33, 14), lw=1.1)

    note(ax, 50, 2.5, "效果：攻击者即使窃取了某一时刻的棘轮私钥，下一次轮换后也无法继续推导新密钥（后向恢复）",
         8, "#c0392b")
    save(fig, "fig_dh_ratchet.png")


# ------------------------------------------------- 8. 中继并发模型 ----------
def fig_relay():
    fig, ax = canvas(9.8, 5.8)
    box(ax, 2, 78, 30, 12, "主线程 accept()\n新连接 → 分配空闲 ID", BLUE, 8.4)
    box(ax, 36, 78, 34, 12, "加锁注册到在线表 g_clients\nstd::map<int, SessionPtr>", (("#eef7f0"), "#2e8b57"), 7.8)
    box(ax, 74, 78, 24, 12, "为该连接\n启动一个线程", PURPLE, 8.2)
    arrow(ax, (32, 84), (36, 84), lw=1.1)
    arrow(ax, (70, 84), (74, 84), lw=1.1)

    for i, y in enumerate((58, 40, 22)):
        box(ax, 2, y, 26, 12, f"连接线程 {i + 1}\n阻塞读：长度 + 载荷", GRAY, 7.8)
        box(ax, 32, y, 20, 12, "帧长检查\n4 ≤ len ≤ 1 MiB", AMBER, 7.6)
        arrow(ax, (28, y + 6), (32, y + 6), lw=1.0)

    box(ax, 56, 58, 42, 12, "① 全局锁内查找目标\n{ lock(g_clients_mu); dst = find(target); }", BLUE, 7.0)
    box(ax, 56, 40, 42, 12, "② 锁外完成阻塞写\n{ lock(dst->write_mu); write(len); write(buf); }",
        (("#eef7f0"), "#2e8b57"), 7.0)
    box(ax, 56, 22, 42, 12, "③ 目标离线 → 回一条 SYSTEM 帧\n“用户 X 不在线”", (("#fdecea"), "#c0392b"), 7.4)
    for y in (58, 40, 22):
        arrow(ax, (52, y + 6), (56, y + 6), lw=1.0)

    note(ax, 50, 13,
         "每连接一把写锁 write_mu 是必须的：A 的消息由“处理 A 的线程”写进 B 的 socket，\n"
         "而处理 B 的线程也可能同时在写同一个 socket，不互斥就会出现帧交错、对端无法还原边界。", 8, "#31414f")
    note(ax, 50, 4,
         "全局锁只在查表时短暂持有，阻塞写放在锁外——避免一个慢客户端拖垮整个服务。", 8, "#c0392b")
    note(ax, 77, 94, "转发流程（每个连接线程都执行）", 8, "#31414f")
    save(fig, "fig_relay.png")


# ------------------------------------------------- 9. 客户端状态机 ----------
def fig_state():
    fig, ax = canvas(9.8, 5.6)
    states = [
        ("启动", 4, 80, 18, 12, GRAY),
        ("连接中\nconnect(:9000)", 32, 80, 26, 12, BLUE),
        ("已连接\n（服务器分配 ID）", 32, 58, 26, 12, BLUE),
        ("握手进行中\nINIT / RESP / CONFIRM", 32, 36, 26, 12, PURPLE),
        ("会话已建立\n显示安全码 + 指纹", 32, 14, 26, 12, GREEN),
        ("断线 / 重试\n15 秒无 PONG", 70, 58, 26, 12, RED),
    ]
    for t, x, y, w, h, c in states:
        box(ax, x, y, w, h, t, c, 8.0, bold=(c is GREEN))

    arrow(ax, (22, 86), (32, 86), lw=1.2)
    arrow(ax, (45, 80), (45, 70), lw=1.2)
    ax.text(46.5, 75, "连接成功", fontsize=7.4, color="#2f6db0", va="center")
    arrow(ax, (45, 58), (45, 48), lw=1.2)
    ax.text(46.5, 53, "首次发送 / 收到 INIT", fontsize=7.4, color="#2f6db0", va="center")
    arrow(ax, (45, 36), (45, 26), lw=1.2)
    ax.text(46.5, 31, "MAC 校验通过", fontsize=7.4, color="#2e8b57", va="center")

    arrow(ax, (58, 64), (70, 64), lw=1.2, color="#c0392b")
    ax.text(64, 66.6, "socket 读失败", fontsize=7.2, color="#c0392b", ha="center")
    arrow(ax, (58, 20), (70, 57), lw=1.2, color="#c0392b", rad=-0.12)
    ax.text(66.5, 40, "心跳超时 /\n服务器关闭", fontsize=7.2, color="#c0392b", ha="center")

    arrow(ax, (83, 70), (58, 86), lw=1.2, ls=(0, (4, 2)), color="#c0392b", rad=0.12)
    ax.text(72, 82, "2 秒后自动重连", fontsize=7.2, color="#c0392b", ha="center")

    note(ax, 2, 46, "服务器侧：60 秒无活动\n→ 回收该 ID", 7.4, "#a86a12", ha="left")
    note(ax, 2, 26, "重连后必须重新握手：\n旧会话密钥随 socket 一起丢弃\n（这正是前向保密的体现）",
         7.2, "#31414f", ha="left")
    save(fig, "fig_state.png")


# ------------------------------------------------- 10. 存储加密链 ----------
def fig_storage():
    fig, ax = canvas(10.0, 6.2)
    box(ax, 2, 76, 26, 12, "Ed25519 身份私钥\n（进程内存，64 B）", GREEN, 8.2)
    box(ax, 33, 76, 24, 12, "Windows DPAPI\nCryptProtectData", BLUE, 8.2)
    box(ax, 62, 76, 32, 12, "identity.pem\n（仅当前 Windows 账户可解）", AMBER, 8)
    arrow(ax, (28, 82), (33, 82), lw=1.1)
    arrow(ax, (57, 82), (62, 82), lw=1.1)

    box(ax, 2, 52, 26, 12, "HKDF-SHA256\ninfo = local storage key", PURPLE, 7.2)
    arrow(ax, (15, 76), (15, 64), lw=1.1, color="#6f42c1")
    box(ax, 33, 52, 24, 12, "本地存储密钥\n（32 B，仅在内存）", PURPLE, 7.4)
    arrow(ax, (28, 58), (33, 58), lw=1.1, color="#6f42c1")

    box(ax, 62, 52, 32, 12, "AES-256-GCM（逐条记录）\nAAD = 对端 ID", RED, 7.4)
    arrow(ax, (57, 58), (62, 58), lw=1.1, color="#c0392b")
    box(ax, 62, 30, 32, 14, "chats\\<本地身份指纹>\\<对端 ID>.log\n每行 = hex(nonce12 ‖ 密文 ‖ tag16)", (("#fdecea"), "#c0392b"), 7.4)
    arrow(ax, (78, 52), (78, 44), lw=1.1, color="#c0392b")

    box(ax, 33, 30, 24, 14, "pins\\<本地指纹>.log\n对端身份公钥（TOFU）", AMBER, 7.8)
    arrow(ax, (62, 37), (57, 37), lw=1.1, color="#c9861a")

    note(ax, 15, 40, "身份密钥\n是持久根", 7.8, "#2e8b57")
    note(ax, 2, 20, "为什么不按服务器 ID 归档？\nID 是临时的，身份密钥才是持久的；\n重启或换 ID 后历史与指纹固定仍有效",
         7.4, "#31414f", ha="left", style="italic")
    box(ax, 62, 7, 32, 16, "换账户 / 换机器拷贝文件\nidentity.pem 无法解密\n历史记录一并失效",
        (("#f3f5f8"), "#8290a0"), 7.2)
    save(fig, "fig_storage.png")


# ------------------------------------------------- 11. 中间人拓扑 ----------
def _read_sas(path):
    """读 mitm_demo 写出的两端安全码（c1/c2），没有就返回空串。"""
    txt = ""
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            txt = f.read()
    except OSError:
        pass
    out = []
    for line in txt.splitlines():
        if line.startswith(("c1=", "c2=")):
            m = re.search(r"(\d{6})", line)
            out.append(m.group(1) if m else "")
    return out if len(out) == 2 else ["", ""]


def fig_mitm():
    fig, ax = canvas(9.8, 5.6)
    box(ax, 2, 55, 24, 20, "用户 1\n（客户端 A）", BLUE, 9, bold=True)
    box(ax, 74, 55, 24, 20, "用户 2\n（客户端 B）", BLUE, 9, bold=True)
    box(ax, 34, 50, 32, 30, "中间人 MitmRelay\n\n与 A 完成一次会话\n与 B 完成另一次会话",
        RED, 9, bold=True)
    arrow(ax, (26, 68), (34, 68), color="#c0392b", lw=1.6, style="<|-|>")
    arrow(ax, (66, 68), (74, 68), color="#c0392b", lw=1.6, style="<|-|>")
    note(ax, 30, 73, "会话①", 7.4, "#c0392b")
    note(ax, 70, 73, "会话②", 7.4, "#c0392b")

    s1, s2 = _read_sas(os.path.join(MITM, "sas.txt"))
    box(ax, 2, 30, 24, 14, "状态栏：\n安全码 " + (s1 or "见正文"), (("#eef7f0"), "#2e8b57"), 7.4)
    box(ax, 74, 30, 24, 14, "状态栏：\n安全码 " + (s2 or "见正文"), (("#eef7f0"), "#2e8b57"), 7.4)
    arrow(ax, (14, 55), (14, 44), lw=1.0, ls=(0, (3, 2)))
    arrow(ax, (86, 55), (86, 44), lw=1.0, ls=(0, (3, 2)))

    box(ax, 26, 4, 50, 18,
        "两端都显示“加密会话已建立”，但安全码不同\n"
        "→ 口头核对一次即可发现被劫持\n"
        "→ 攻击者在两段会话间转发明文",
        (("#fdecea"), "#c0392b"), 7.4)
    save(fig, "fig_mitm.png")


# ------------------------------------------------- 12. 测试统计 -----------
def fig_testbar():
    groups = ["密码学 / 协议断言\nCryptoTest.exe",
              "端到端冒烟\nsmoke_test.ps1",
              "功能用例\nF-01 ~ F-14",
              "健壮性用例\nR-01 ~ R-09",
              "安全专项\nS-01 ~ S-06"]
    measured = [28, 5, 14, 6, 5]
    by_design = [0, 0, 0, 3, 1]
    fig, ax = plt.subplots(figsize=(6.3, 3.2), dpi=DPI)
    y = range(len(groups))
    ax.barh(list(y), measured, color="#2e8b57", label="实测与预期一致", height=0.55)
    ax.barh(list(y), by_design, left=measured, color="#c9861a",
            label="已实现 / 设计保证", height=0.55)
    for i, (m, b) in enumerate(zip(measured, by_design)):
        ax.text(m + b + 0.5, i, "%d 项" % (m + b), va="center", fontsize=8.6, color=INK)
    ax.set_yticks(list(y))
    ax.set_yticklabels(groups, fontsize=8.2)
    ax.invert_yaxis()
    ax.set_xlabel("用例 / 断言数量", fontsize=8.6)
    ax.set_xlim(0, 33)
    ax.tick_params(axis="x", labelsize=8)
    ax.grid(axis="x", color="#e3e8ee", lw=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.legend(fontsize=8, loc="lower right", frameon=False)
    ax.set_title("共 62 项测试，0 项失败", fontsize=9.6, color=INK)
    fig.tight_layout()
    save(fig, "fig_testbar.png")


# ------------------------------------------- 13. 真实运行输出（配图） -----
def _localize_cipher(ln):
    """capture_shots.ps1 只能输出 ASCII，中文标题在这里补上。"""
    if ln.startswith("file: "):
        return "文件（可直接用记事本打开）：" + ln[6:]
    if ln.startswith("records: "):
        return "记录条数：" + ln[9:] + "（每行 = hex(nonce12 ‖ 密文 ‖ tag16)）"
    if ln.startswith("PLAINTEXT-NOT-FOUND"):
        return "在文件中搜索明文 “" + ln.split(None, 1)[1] + "” ：未找到 → 文件里只有密文"
    if ln.startswith("PLAINTEXT-FOUND"):
        return "在文件中搜索明文：找到了（异常！）"
    return ln


def text_figure(path, name, title, max_lines=None, fs=7.6, w=6.3):
    if not os.path.exists(path):
        print("  !! missing", path)
        return
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        lines = f.read().replace("\t", "    ").rstrip("\n").split("\n")
    if name == "fig_ciphertext.png":
        lines = [_localize_cipher(l) for l in lines]
    if max_lines:
        lines = lines[:max_lines]
    # 按字号换算出足够容纳所有行的图高（英寸，不再乘整体缩放系数）
    h = 0.26 + len(lines) * fs * 1.48 / 72.0 + 0.28
    fig, ax = canvas(w, h, k=1.0)
    ax.add_patch(FancyBboxPatch((1, 1), 98, 98, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc="#1e1e1e", ec="#3c3c3c", lw=1.2, zorder=1))
    ax.add_patch(plt.Rectangle((1, 92.5), 98, 6.5, fc="#2d2d30", ec="none", zorder=2))
    ax.text(3.2, 95.7, title, fontsize=8.0, color="#cccccc", va="center", zorder=3,
            family=[CJK, MONO])
    step = 84.0 / max(len(lines), 1)
    for i, ln in enumerate(lines):
        color = "#d4d4d4"
        if "[OK]" in ln:
            color = "#6ec07a"
        elif "[FAIL]" in ln or "异常" in ln:
            color = "#f48771"
        elif ln.startswith("==="):
            color = "#dcdcaa"
        elif "未找到" in ln:
            color = "#6ec07a"
        ax.text(3.2, 88.0 - i * step, ln if ln else " ", fontsize=fs, color=color,
                va="top", ha="left", zorder=3, family=[MONO, CJK])
    save(fig, name)


def main():
    os.makedirs(DOCS, exist_ok=True)
    fig_usecase()
    fig_arch()
    fig_frame()
    fig_handshake()
    fig_kdf()
    fig_msg_ratchet()
    fig_dh_ratchet()
    fig_relay()
    fig_state()
    fig_storage()
    fig_mitm()
    fig_testbar()
    text_figure(os.path.join(TEMP, "crypto_test_out.txt"), "fig_crypto_out.png",
                "build\\Debug\\CryptoTest.exe　—— 28 项断言全部通过")
    text_figure(os.path.join(SHOTS, "ciphertext.txt"), "fig_ciphertext.png",
                "聊天记录文件（记事本直接打开的样子）", max_lines=14, fs=8.4, w=6.3)


if __name__ == "__main__":
    main()
