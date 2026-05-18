import base64
import hashlib
import os
import random
import struct
import threading
from tkinter import (
    Tk, Label, Button, Entry, Text, END,
    filedialog, messagebox, StringVar,
    Frame, Canvas, BooleanVar, IntVar
)
from tkinter import ttk
from PIL import Image, ImageTk

# Cryptography 
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("pip install cryptography pillow")

END_MARKER = "<<END_STEG_2024>>"   # Web интерфейстэй ижил


def derive_key(password: str) -> bytes:
    """SHA-256(password) → 32-byte AES key  (Web Crypto-тай яг адил)"""
    return hashlib.sha256(password.encode("utf-8")).digest()


def encrypt_aes_gcm(plaintext: str, password: str) -> str:
    """
    AES-256-GCM шифрлэлт.
    Гаралт: base64( IV[12] + ciphertext )  — Web Crypto-тай нийцтэй
    """
    key  = derive_key(password)
    iv   = os.urandom(12)
    ct   = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    raw  = iv + ct
    return base64.b64encode(raw).decode("ascii")


def decrypt_aes_gcm(b64_token: str, password: str) -> str:
    """AES-256-GCM тайлалт.  Буруу password → ValueError."""
    key      = derive_key(password)
    raw      = base64.b64decode(b64_token)
    iv, ct   = raw[:12], raw[12:]
    pt       = AESGCM(key).decrypt(iv, ct, None)
    return pt.decode("utf-8")


# Binary helpers 
def text_to_bits(text: str) -> str:
    return "".join(format(ord(c), "08b") for c in text)


def bits_to_text(bits: str) -> str:
    return "".join(
        chr(int(bits[i:i+8], 2))
        for i in range(0, len(bits) - 7, 8)
    )


# Random embedding (Web-тэй ижил shuffle алгоритм)
def _web_rng(seed: int):
    s = seed ^ 0x9E3779B9
    s &= 0xFFFFFFFF
    while True:
        s ^= s >> 16;  s &= 0xFFFFFFFF
        s  = (s * 0x45D9F3B) & 0xFFFFFFFF
        s ^= s >> 16;  s &= 0xFFFFFFFF
        s  = (s * 0x45D9F3B) & 0xFFFFFFFF
        s ^= s >> 16;  s &= 0xFFFFFFFF
        yield s / 0x100000000


def web_shuffle(indices: list, seed: int) -> list:
    arr = indices[:]
    rng = _web_rng(seed)
    for i in range(len(arr) - 1, 0, -1):
        j = int(next(rng) * (i + 1))
        arr[i], arr[j] = arr[j], arr[i]
    return arr


def build_channel_indices(width: int, height: int,
                          use_random: bool, seed: int) -> list:
    # PIL getdata() → (R,G,B) tuple → flat: R=i*4, G=i*4+1, B=i*4+2
    indices = []
    for i in range(width * height):
        indices.extend([i * 4, i * 4 + 1, i * 4 + 2])
    if use_random:
        indices = web_shuffle(indices, seed)
    return indices


# Steganography core 
def encode_image(src: str, dst: str, secret: str,
                 password: str, use_random: bool = False,
                 seed: int = 42) -> dict:
    img    = Image.open(src).convert("RGB")
    w, h   = img.size
    pixels = list(img.getdata())

    flat = []
    for r, g, b in pixels:
        flat.extend([r, g, b, 0])

    cipher  = encrypt_aes_gcm(secret, password)
    payload = cipher + END_MARKER
    bits    = text_to_bits(payload)
    total   = w * h * 3

    if len(bits) > total:
        raise ValueError(
            f"Нууц текст хэт урт!\n"
            f"Шаардлагатай: {len(bits):,} бит\n"
            f"Зургийн багтаамж: {total:,} бит"
        )

    indices = build_channel_indices(w, h, use_random, seed)

    for i, bit in enumerate(bits):
        idx      = indices[i]
        flat[idx] = (flat[idx] & ~1) | int(bit)

    # Rebuild image
    new_pixels = [
        (flat[i], flat[i+1], flat[i+2])
        for i in range(0, len(flat), 4)
    ]
    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    out.save(dst, format="PNG")

    used_pct = round(len(bits) / total * 100, 2)
    return {"bits_used": len(bits), "bits_total": total,
            "used_pct": used_pct, "chars": len(secret)}


def decode_image(stego: str, password: str,
                 use_random: bool = False, seed: int = 42) -> str:
    img    = Image.open(stego).convert("RGB")
    w, h   = img.size
    pixels = list(img.getdata())

    flat = []
    for r, g, b in pixels:
        flat.extend([r, g, b, 0])

    indices = build_channel_indices(w, h, use_random, seed)

    bits = ""
    text = ""
    for idx in indices:
        bits += str(flat[idx] & 1)
        if len(bits) % 8 == 0:
            text += chr(int(bits[-8:], 2))
            if END_MARKER in text:
                cipher = text.split(END_MARKER)[0]
                return decrypt_aes_gcm(cipher, password)

    raise ValueError("Нууц мэдээлэл олдсонгүй.")


def get_capacity_bytes(path: str) -> int:
    img = Image.open(path).convert("RGB")
    return (img.width * img.height * 3) // 8


# Color palette 
BG      = "#0D1117"
CARD    = "#161B22"
INPUT   = "#21262D"
BORDER  = "#30363D"
ACCENT  = "#58A6FF"
GREEN   = "#3FB950"
RED     = "#F85149"
AMBER   = "#F0A030"
TXT     = "#E6EDF3"
TXTS    = "#8B949E"


# GUI 
class StegoCrypt:
    def __init__(self, root: Tk):
        self.root      = root
        self.enc_file  = ""
        self.dec_file  = ""
        self.cap_bytes = 0
        self._setup_window()
        self._build_ui()

    # Window 
    def _setup_window(self):
        self.root.title("StegoCrypt v2.0")
        self.root.geometry("820x660")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(
            f"+{(sw-820)//2}+{(sh-660)//2}"
        )

    # Full UI 
    def _build_ui(self):
        # Header
        hdr = Frame(self.root, bg=CARD, height=56)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        Label(hdr, text="🔐  StegoCrypt",
              font=("Courier New", 16, "bold"), bg=CARD, fg=ACCENT
              ).pack(side="left", padx=20, pady=10)
        Label(hdr, text="AES-256-GCM + LSB  •  Web-compatible  •  v2.0",
              font=("Courier New", 9), bg=CARD, fg=TXTS
              ).pack(side="left", pady=10)

        # Tab bar
        tab_frame = Frame(self.root, bg=BG)
        tab_frame.pack(fill="x", padx=20, pady=(14, 0))
        self.tab_var = StringVar(value="encode")

        self.tab_enc = Button(tab_frame, text="🔒  Encode",
                              font=("Courier New", 10, "bold"),
                              bg=CARD, fg=TXT, relief="flat", bd=0,
                              padx=24, pady=8, cursor="hand2",
                              command=lambda: self._switch("encode"))
        self.tab_enc.pack(side="left")

        self.tab_dec = Button(tab_frame, text="🔓  Decode",
                              font=("Courier New", 10, "bold"),
                              bg=BG, fg=TXTS, relief="flat", bd=0,
                              padx=24, pady=8, cursor="hand2",
                              command=lambda: self._switch("decode"))
        self.tab_dec.pack(side="left")

        sep = Frame(self.root, bg=BORDER, height=1)
        sep.pack(fill="x", padx=20)

        # Content area
        self.content = Frame(self.root, bg=BG)
        self.content.pack(fill="both", expand=True, padx=20, pady=14)

        # Status bar — _switch()-аас өмнө үүсгэх ёстой
        sb = Frame(self.root, bg=CARD, height=30)
        sb.pack(fill="x", side="bottom"); sb.pack_propagate(False)
        self._dot = Label(sb, text="●", font=("Courier New", 10),
                          bg=CARD, fg=TXTS)
        self._dot.pack(side="left", padx=(14, 4))
        self._status_var = StringVar(value="Бэлэн")
        Label(sb, textvariable=self._status_var,
              font=("Courier New", 9), bg=CARD, fg=TXTS
              ).pack(side="left")

        self._build_encode_panel()
        self._build_decode_panel()
        self._switch("encode")

    # Tab switch 
    def _switch(self, tab: str):
        self.tab_var.set(tab)
        if tab == "encode":
            self.tab_enc.config(bg=CARD, fg=TXT)
            self.tab_dec.config(bg=BG,   fg=TXTS)
            self.enc_panel.pack(fill="both", expand=True)
            self.dec_panel.pack_forget()
        else:
            self.tab_dec.config(bg=CARD, fg=TXT)
            self.tab_enc.config(bg=BG,   fg=TXTS)
            self.dec_panel.pack(fill="both", expand=True)
            self.enc_panel.pack_forget()
        self._set_status("Бэлэн", TXTS)

    # Encode panel
    def _build_encode_panel(self):
        p = Frame(self.content, bg=BG)
        self.enc_panel = p

        # Image row
        self._section(p, "📁  ЗУРГИЙН ФАЙЛ")
        irow = Frame(p, bg=BG)
        irow.pack(fill="x", pady=(0, 10))
        self.enc_img_var = StringVar()
        Entry(irow, textvariable=self.enc_img_var,
              font=("Courier New", 10), bg=INPUT, fg=TXT,
              insertbackground=ACCENT, relief="flat", bd=0
              ).pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        self.enc_img_var.trace_add("write", lambda *_: self._on_enc_img())
        Button(irow, text="Browse", font=("Courier New", 9, "bold"),
               bg=ACCENT, fg=BG, relief="flat", bd=0, padx=12, pady=6,
               cursor="hand2",
               command=lambda: self._browse(self.enc_img_var)
               ).pack(side="right")

        # Preview + capacity
        prev_row = Frame(p, bg=BG)
        prev_row.pack(fill="x", pady=(0, 10))
        self.enc_canvas = Canvas(prev_row, width=72, height=72,
                                 bg=INPUT, highlightthickness=0)
        self.enc_canvas.pack(side="left", padx=(0, 12))
        info = Frame(prev_row, bg=BG)
        info.pack(side="left", fill="x", expand=True)
        self.enc_img_info = Label(info, text="", font=("Courier New", 9),
                                  bg=BG, fg=TXTS, anchor="w")
        self.enc_img_info.pack(fill="x")
        cap_lbl_row = Frame(info, bg=BG)
        cap_lbl_row.pack(fill="x", pady=(4, 2))
        Label(cap_lbl_row, text="Багтаамжийн ашиглалт",
              font=("Courier New", 8), bg=BG, fg=TXTS).pack(side="left")
        self.enc_pct_lbl = Label(cap_lbl_row, text="0%",
                                  font=("Courier New", 8), bg=BG, fg=TXTS)
        self.enc_pct_lbl.pack(side="right")
        bar_bg = Frame(info, bg=BORDER, height=5)
        bar_bg.pack(fill="x")
        self.enc_bar = Frame(bar_bg, bg=BORDER, height=5, width=0)
        self.enc_bar.place(x=0, y=0)

        # Password
        self._section(p, "🔑  PASSWORD")
        pw_row = Frame(p, bg=BG)
        pw_row.pack(fill="x", pady=(0, 10))
        self.enc_pw = Entry(pw_row, font=("Courier New", 11),
                            bg=INPUT, fg=TXT, insertbackground=ACCENT,
                            relief="flat", bd=0, show="●")
        self.enc_pw.pack(side="left", fill="x", expand=True, ipady=7, padx=(0,8))
        Button(pw_row, text="👁", font=("Courier New", 10),
               bg=INPUT, fg=TXTS, relief="flat", bd=0, padx=8, cursor="hand2",
               command=lambda: self._toggle_show(self.enc_pw)
               ).pack(side="right")

        # Message
        self._section(p, "✉️  НУУЦ ТЕКСТ")
        self.enc_msg = Text(p, font=("Courier New", 10), bg=INPUT, fg=TXT,
                            insertbackground=ACCENT, relief="flat", bd=0,
                            height=5, wrap="word")
        self.enc_msg.pack(fill="x", pady=(0, 2))
        self.enc_msg.bind("<KeyRelease>", lambda _: self._update_cap_bar())
        self.enc_char_lbl = Label(p, text="0 тэмдэгт",
                                  font=("Courier New", 8), bg=BG, fg=TXTS,
                                  anchor="e")
        self.enc_char_lbl.pack(fill="x", pady=(0, 10))

        # Options
        self._section(p, "⚙️  ТОХИРГОО")
        opt_row = Frame(p, bg=BG)
        opt_row.pack(fill="x")
        self.enc_rand = BooleanVar(value=False)
        ttk.Checkbutton(opt_row, text=" Random embedding  (steganalysis-д тэсвэртэй)",
                        variable=self.enc_rand,
                        command=lambda: self._toggle_seed(
                            self.enc_rand, self.enc_seed_row)
                        ).pack(side="left")
        self.enc_seed_row = Frame(p, bg=BG)
        Label(self.enc_seed_row, text="Seed:",
              font=("Courier New", 9), bg=BG, fg=TXTS).pack(side="left")
        self.enc_seed = Entry(self.enc_seed_row, width=7,
                              font=("Courier New", 9),
                              bg=INPUT, fg=TXT, relief="flat", bd=0)
        self.enc_seed.insert(0, "42")
        self.enc_seed.pack(side="left", ipady=4, padx=4)
        Label(self.enc_seed_row,
              text="(decode-д ижил seed ашиглана)",
              font=("Courier New", 8), bg=BG, fg=TXTS).pack(side="left")

        # Buttons
        btn_row = Frame(p, bg=BG)
        btn_row.pack(fill="x", pady=12)
        Button(btn_row, text="🔒  Encode",
               font=("Courier New", 10, "bold"),
               bg=GREEN, fg=BG, relief="flat", bd=0,
               padx=20, pady=9, cursor="hand2",
               command=self._encode).pack(side="left", padx=(0, 8))
        Button(btn_row, text="Цэвэрлэх",
               font=("Courier New", 10),
               bg=CARD, fg=TXTS, relief="flat", bd=0,
               padx=16, pady=9, cursor="hand2",
               command=self._clear).pack(side="left")

    # Decode panel 
    def _build_decode_panel(self):
        p = Frame(self.content, bg=BG)
        self.dec_panel = p

        self._section(p, "📁  STEGO ЗУРАГ")
        drow = Frame(p, bg=BG)
        drow.pack(fill="x", pady=(0, 10))
        self.dec_img_var = StringVar()
        Entry(drow, textvariable=self.dec_img_var,
              font=("Courier New", 10), bg=INPUT, fg=TXT,
              insertbackground=ACCENT, relief="flat", bd=0
              ).pack(side="left", fill="x", expand=True, ipady=7, padx=(0,8))
        self.dec_img_var.trace_add("write", lambda *_: self._on_dec_img())
        Button(drow, text="Browse",
               font=("Courier New", 9, "bold"),
               bg=ACCENT, fg=BG, relief="flat", bd=0, padx=12, pady=6,
               cursor="hand2",
               command=lambda: self._browse(self.dec_img_var)
               ).pack(side="right")

        prev2 = Frame(p, bg=BG)
        prev2.pack(fill="x", pady=(0, 10))
        self.dec_canvas = Canvas(prev2, width=72, height=72,
                                 bg=INPUT, highlightthickness=0)
        self.dec_canvas.pack(side="left", padx=(0, 12))
        self.dec_img_info = Label(prev2, text="",
                                  font=("Courier New", 9), bg=BG, fg=TXTS)
        self.dec_img_info.pack(side="left")

        self._section(p, "🔑  PASSWORD")
        pw2_row = Frame(p, bg=BG)
        pw2_row.pack(fill="x", pady=(0, 10))
        self.dec_pw = Entry(pw2_row, font=("Courier New", 11),
                            bg=INPUT, fg=TXT, insertbackground=ACCENT,
                            relief="flat", bd=0, show="●")
        self.dec_pw.pack(side="left", fill="x", expand=True, ipady=7, padx=(0,8))
        Button(pw2_row, text="👁", font=("Courier New", 10),
               bg=INPUT, fg=TXTS, relief="flat", bd=0, padx=8, cursor="hand2",
               command=lambda: self._toggle_show(self.dec_pw)
               ).pack(side="right")

        self._section(p, "⚙️  ТОХИРГОО")
        opt2 = Frame(p, bg=BG)
        opt2.pack(fill="x")
        self.dec_rand = BooleanVar(value=False)
        ttk.Checkbutton(opt2, text=" Random embedding  (encode-д ашигласан бол идэвхжүүлнэ)",
                        variable=self.dec_rand,
                        command=lambda: self._toggle_seed(
                            self.dec_rand, self.dec_seed_row)
                        ).pack(side="left")
        self.dec_seed_row = Frame(p, bg=BG)
        Label(self.dec_seed_row, text="Seed:",
              font=("Courier New", 9), bg=BG, fg=TXTS).pack(side="left")
        self.dec_seed = Entry(self.dec_seed_row, width=7,
                              font=("Courier New", 9),
                              bg=INPUT, fg=TXT, relief="flat", bd=0)
        self.dec_seed.insert(0, "42")
        self.dec_seed.pack(side="left", ipady=4, padx=4)

        btn2 = Frame(p, bg=BG)
        btn2.pack(fill="x", pady=12)
        Button(btn2, text="🔓  Decode",
               font=("Courier New", 10, "bold"),
               bg=ACCENT, fg=BG, relief="flat", bd=0,
               padx=20, pady=9, cursor="hand2",
               command=self._decode).pack(side="left", padx=(0, 8))
        Button(btn2, text="Цэвэрлэх",
               font=("Courier New", 10),
               bg=CARD, fg=TXTS, relief="flat", bd=0,
               padx=16, pady=9, cursor="hand2",
               command=self._clear).pack(side="left")

        # Result
        self._section(p, "📤  ҮР ДҮН")
        self.dec_result = Text(p, font=("Courier New", 10),
                               bg=INPUT, fg=GREEN,
                               insertbackground=ACCENT,
                               relief="flat", bd=0,
                               height=5, wrap="word",
                               state="disabled")
        self.dec_result.pack(fill="x")
        copy_row = Frame(p, bg=BG)
        copy_row.pack(fill="x", pady=(4, 0))
        Button(copy_row, text="📋 Хуулах",
               font=("Courier New", 8),
               bg=INPUT, fg=TXTS, relief="flat", bd=0,
               padx=8, pady=4, cursor="hand2",
               command=self._copy_result).pack(side="right")

    # Helpers 
    def _section(self, parent, title: str):
        Label(parent, text=title, font=("Courier New", 8, "bold"),
              bg=BG, fg=TXTS).pack(anchor="w", pady=(6, 3))

    def _browse(self, var: StringVar):
        p = filedialog.askopenfilename(
            title="PNG зураг сонгох",
            filetypes=[("PNG files", "*.png")]
        )
        if p:
            var.set(p)

    def _toggle_show(self, entry: Entry):
        entry.config(show="" if entry.cget("show") == "●" else "●")

    def _toggle_seed(self, flag: BooleanVar, row: Frame):
        if flag.get():
            row.pack(fill="x", pady=(4, 0))
        else:
            row.pack_forget()

    def _set_status(self, msg: str, color: str = TXTS):
        self._status_var.set(msg)
        self._dot.config(fg=color)

    def _update_preview(self, canvas: Canvas, path: str):
        try:
            img   = Image.open(path).convert("RGB")
            scale = min(72 / img.width, 72 / img.height)
            thumb = img.resize(
                (int(img.width * scale), int(img.height * scale)),
                Image.LANCZOS
            )
            self._tk_img = ImageTk.PhotoImage(thumb)
            canvas.delete("all")
            canvas.create_image(36, 36, image=self._tk_img)
        except Exception:
            pass

    def _on_enc_img(self):
        p = self.enc_img_var.get().strip()
        if not os.path.isfile(p):
            return
        try:
            img = Image.open(p).convert("RGB")
            w, h = img.size
            self.cap_bytes = w * h * 3 // 8
            self.enc_img_info.config(
                text=f"{w}×{h} px  •  ~{self.cap_bytes:,} байт багтаамж"
            )
            self._update_preview(self.enc_canvas, p)
            self._update_cap_bar()
        except Exception:
            pass

    def _on_dec_img(self):
        p = self.dec_img_var.get().strip()
        if not os.path.isfile(p):
            return
        try:
            img = Image.open(p).convert("RGB")
            w, h = img.size
            self.dec_img_info.config(text=f"{w}×{h} px")
            self._update_preview(self.dec_canvas, p)
        except Exception:
            pass

    def _update_cap_bar(self):
        txt  = self.enc_msg.get("1.0", END).strip()
        chars = len(txt)
        self.enc_char_lbl.config(text=f"{chars} тэмдэгт")
        if not self.cap_bytes:
            return
        pct  = min(int(chars / self.cap_bytes * 100), 100)
        color = GREEN if pct < 50 else AMBER if pct < 80 else RED
        bar_w = int(self.enc_canvas.winfo_width() * 2 * pct / 100)
        self.enc_bar.config(width=bar_w, bg=color)
        self.enc_pct_lbl.config(text=f"{pct}%")

    def _copy_result(self):
        txt = self.dec_result.get("1.0", END).strip()
        if txt:
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._set_status("Clipboard-д хуулагдлаа ✓", GREEN)

    # Encode action
    def _encode(self):
        src = self.enc_img_var.get().strip()
        pw  = self.enc_pw.get().strip()
        msg = self.enc_msg.get("1.0", END).strip()
        rnd = self.enc_rand.get()

        if not src:
            return messagebox.showerror("Алдаа", "PNG зураг сонгоно уу.")
        if not pw:
            return messagebox.showerror("Алдаа", "Password оруулна уу.")
        if not msg:
            return messagebox.showerror("Алдаа", "Нууц текст хоосон байна.")

        try:
            seed = int(self.enc_seed.get())
        except ValueError:
            return messagebox.showerror("Алдаа", "Seed бүхэл тоо байх ёстой.")

        dst = filedialog.asksaveasfilename(
            title="Хадгалах",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if not dst:
            return

        self._set_status("Encode хийж байна…", AMBER)
        self.root.update()

        def run():
            try:
                info = encode_image(src, dst, msg, pw,
                                    use_random=rnd, seed=seed)
                mode = "Random" if rnd else "Sequential"
                self._set_status(
                    f"✓ Амжилттай  •  {mode} LSB  •  {info['used_pct']}% ашиглав",
                    GREEN
                )
                messagebox.showinfo(
                    "Амжилттай",
                    f"Стего зураг хадгалагдлаа:\n{dst}\n\n"
                    f"Ашигласан: {info['bits_used']:,} / {info['bits_total']:,} бит "
                    f"({info['used_pct']}%)"
                )
            except Exception as e:
                self._set_status("Алдаа гарлаа", RED)
                messagebox.showerror("Алдаа", str(e))

        threading.Thread(target=run, daemon=True).start()

    # Decode action 
    def _decode(self):
        src = self.dec_img_var.get().strip()
        pw  = self.dec_pw.get().strip()
        rnd = self.dec_rand.get()

        if not src:
            return messagebox.showerror("Алдаа", "Зураг сонгоно уу.")
        if not pw:
            return messagebox.showerror("Алдаа", "Password оруулна уу.")

        try:
            seed = int(self.dec_seed.get())
        except ValueError:
            return messagebox.showerror("Алдаа", "Seed бүхэл тоо байх ёстой.")

        self._set_status("Decode хийж байна…", AMBER)
        self.root.update()

        def run():
            try:
                secret = decode_image(src, pw, use_random=rnd, seed=seed)
                self.dec_result.config(state="normal")
                self.dec_result.delete("1.0", END)
                self.dec_result.insert(END, secret)
                self.dec_result.config(state="disabled")
                self._set_status(
                    f"✓ Decode амжилттай.  {len(secret)} тэмдэгт", GREEN
                )
                messagebox.showinfo("Амжилттай",
                                    "Нууц мэдээлэл амжилттай гарлаа!")
            except Exception as e:
                msg = str(e).strip()
                
                if not msg or "tag" in msg.lower() or "invalid" in msg.lower():
                     msg = "Password буруу байна!"
                     
                self._set_status(msg, RED)
                messagebox.showerror("Алдаа", msg)

        threading.Thread(target=run, daemon=True).start()

    # Clear 
    def _clear(self):
        for w in (self.enc_img_var, self.dec_img_var):
            w.set("")
        for e in (self.enc_pw, self.dec_pw):
            e.delete(0, END)
        self.enc_msg.delete("1.0", END)
        self.dec_result.config(state="normal")
        self.dec_result.delete("1.0", END)
        self.dec_result.config(state="disabled")
        for c in (self.enc_canvas, self.dec_canvas):
            c.delete("all")
        self.enc_img_info.config(text="")
        self.dec_img_info.config(text="")
        self.enc_bar.config(width=0)
        self.enc_pct_lbl.config(text="0%")
        self.enc_char_lbl.config(text="0 тэмдэгт")
        self.cap_bytes = 0
        self._set_status("Цэвэрлэгдлээ", TXTS)


# Entry point 
if __name__ == "__main__":
    root = Tk()
    style = ttk.Style(root)
    style.theme_use("default")
    style.configure("TCheckbutton",
                    background=BG, foreground=TXT,
                    font=("Courier New", 9))
    style.map("TCheckbutton",
              background=[("active", BG)],
              foreground=[("active", TXT)])
    StegoCrypt(root)
    root.mainloop()
