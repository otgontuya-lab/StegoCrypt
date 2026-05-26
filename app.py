import base64
import hashlib
import io
import os
import struct
import tarfile
import uuid
import zipfile
from flask import Flask, request, jsonify, send_file, render_template
from PIL import Image
import numpy as np

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("pip install cryptography pillow flask numpy")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB

END_MARKER = "<<END_STEG_2024>>"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), 'outputs')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


# ── Crypto
def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8")).digest()

def encrypt_aes_gcm(plaintext: str, password: str) -> str:
    key = derive_key(password)
    iv  = os.urandom(12)
    ct  = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(iv + ct).decode("ascii")

def decrypt_aes_gcm(b64_token: str, password: str) -> str:
    key     = derive_key(password)
    raw     = base64.b64decode(b64_token)
    iv, ct  = raw[:12], raw[12:]
    pt      = AESGCM(key).decrypt(iv, ct, None)
    return pt.decode("utf-8")


# ── Bit helpers 
def text_to_bits(text: str) -> str:
    return "".join(format(ord(c), "08b") for c in text)

def bits_to_text(bits: str) -> str:
    return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8))


# ── RNG / shuffle 
def _web_rng(seed: int):
    s = seed ^ 0x9E3779B9
    s &= 0xFFFFFFFF
    while True:
        s ^= s >> 16; s &= 0xFFFFFFFF
        s  = (s * 0x45D9F3B) & 0xFFFFFFFF
        s ^= s >> 16; s &= 0xFFFFFFFF
        s  = (s * 0x45D9F3B) & 0xFFFFFFFF
        s ^= s >> 16; s &= 0xFFFFFFFF
        yield s / 0x100000000

def web_shuffle(indices: list, seed: int) -> list:
    arr = indices[:]
    rng = _web_rng(seed)
    for i in range(len(arr)-1, 0, -1):
        j = int(next(rng) * (i+1))
        arr[i], arr[j] = arr[j], arr[i]
    return arr

def build_channel_indices(width, height, use_random, seed):
    indices = []
    for i in range(width * height):
        indices.extend([i*4, i*4+1, i*4+2])
    if use_random:
        indices = web_shuffle(indices, seed)
    return indices



# 1. PNG/BMP — LSB Steganography

def encode_png_lsb(img_bytes: bytes, secret: str, password: str,
                   use_random: bool = False, seed: int = 42) -> tuple:
    img    = Image.open(io.BytesIO(img_bytes)).convert("RGB")
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
            f"Нууц текст хэт урт! Шаардлагатай: {len(bits):,} бит, "
            f"Зургийн багтаамж: {total:,} бит"
        )

    indices = build_channel_indices(w, h, use_random, seed)
    for i, bit in enumerate(bits):
        idx       = indices[i]
        flat[idx] = (flat[idx] & ~1) | int(bit)

    new_pixels = [(flat[i], flat[i+1], flat[i+2]) for i in range(0, len(flat), 4)]
    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    buf = io.BytesIO()
    out.save(buf, format="PNG")
    buf.seek(0)

    used_pct = round(len(bits) / total * 100, 2)
    return buf.getvalue(), {
        "bits_used": len(bits), "bits_total": total,
        "used_pct": used_pct, "chars": len(secret),
        "width": w, "height": h, "method": "PNG LSB"
    }

def decode_png_lsb(img_bytes: bytes, password: str,
                   use_random: bool = False, seed: int = 42) -> str:
    img    = Image.open(io.BytesIO(img_bytes)).convert("RGB")
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



# 2. JPEG — DCT Coefficient Steganography (F5-style LSB in AC coefficients)

def _dct2(block):
    from scipy.fft import dctn
    return dctn(block.astype(float), norm='ortho')

def _idct2(block):
    from scipy.fft import idctn
    return idctn(block, norm='ortho')

def encode_jpeg_dct(img_bytes: bytes, secret: str, password: str,
                    quality: int = 85) -> tuple:
    try:
        from scipy.fft import dctn, idctn
    except ImportError:
        raise ValueError("scipy шаардлагатай: pip install scipy")

    cipher  = encrypt_aes_gcm(secret, password)
    payload = cipher + END_MARKER
    bits    = text_to_bits(payload)
    bit_idx = 0
    total_bits = len(bits)

    img = Image.open(io.BytesIO(img_bytes)).convert("YCbCr")
    arr = np.array(img, dtype=float)
    h, w, _ = arr.shape

    # Зөвхөн Y (luminance) channel дээр хийнэ
    Y = arr[:, :, 0]

    # 8×8 блок дутуу бол pad хийнэ
    ph = (8 - h % 8) % 8
    pw = (8 - w % 8) % 8
    Y_pad = np.pad(Y, ((0, ph), (0, pw)), mode='edge')
    bh, bw = Y_pad.shape

    modified = Y_pad.copy()
    capacity = 0
    for by in range(0, bh, 8):
        for bx in range(0, bw, 8):
            block = Y_pad[by:by+8, bx:bx+8]
            dct_block = dctn(block, norm='ortho')
            # AC коэффициентүүд (DC-г орхино: [0,0])
            for i in range(8):
                for j in range(8):
                    if i == 0 and j == 0:
                        continue
                    coeff = int(dct_block[i, j])
                    if coeff != 0:
                        capacity += 1
                        if bit_idx < total_bits:
                            coeff = (coeff & ~1) | int(bits[bit_idx])
                            bit_idx += 1
                        dct_block[i, j] = float(coeff)
            modified[by:by+8, bx:bx+8] = idctn(dct_block, norm='ortho')

    if bit_idx < total_bits:
        raise ValueError(
            f"JPEG зургийн DCT багтаамж хүрэлцэхгүй. "
            f"Шаардлагатай: {total_bits} бит, багтаамж: {capacity} бит"
        )

    # Rebuild image
    modified_crop = np.clip(modified[:h, :w], 0, 255)
    arr[:, :, 0] = modified_crop
    out_img = Image.fromarray(np.uint8(arr), "YCbCr").convert("RGB")

    buf = io.BytesIO()
    out_img.save(buf, format="JPEG", quality=quality, subsampling=0)
    buf.seek(0)

    used_pct = round(bit_idx / capacity * 100, 2) if capacity else 0
    return buf.getvalue(), {
        "bits_used": bit_idx, "bits_total": capacity,
        "used_pct": used_pct, "chars": len(secret),
        "width": w, "height": h, "method": "JPEG DCT"
    }

def decode_jpeg_dct(img_bytes: bytes, password: str) -> str:
    try:
        from scipy.fft import dctn
    except ImportError:
        raise ValueError("scipy шаардлагатай: pip install scipy")

    img = Image.open(io.BytesIO(img_bytes)).convert("YCbCr")
    arr = np.array(img, dtype=float)
    h, w, _ = arr.shape
    Y = arr[:, :, 0]

    ph = (8 - h % 8) % 8
    pw = (8 - w % 8) % 8
    Y_pad = np.pad(Y, ((0, ph), (0, pw)), mode='edge')
    bh, bw = Y_pad.shape

    bits = ""
    text = ""
    for by in range(0, bh, 8):
        for bx in range(0, bw, 8):
            block = Y_pad[by:by+8, bx:bx+8]
            dct_block = dctn(block, norm='ortho')
            for i in range(8):
                for j in range(8):
                    if i == 0 and j == 0:
                        continue
                    coeff = int(dct_block[i, j])
                    if coeff != 0:
                        bits += str(coeff & 1)
                        if len(bits) % 8 == 0:
                            text += chr(int(bits[-8:], 2))
                            if END_MARKER in text:
                                cipher = text.split(END_MARKER)[0]
                                return decrypt_aes_gcm(cipher, password)

    raise ValueError("Нууц мэдээлэл олдсонгүй.")



# 3. ZIP — Comment field steganography

def encode_zip(zip_bytes: bytes, secret: str, password: str) -> tuple:
    cipher  = encrypt_aes_gcm(secret, password)
    payload = (cipher + END_MARKER).encode("utf-8")

    if len(payload) > 65535:
        raise ValueError("Нууц текст хэт урт! ZIP comment талбар 65535 байт хүртэл.")

    # Read original zip, rewrite with comment
    in_buf  = io.BytesIO(zip_bytes)
    out_buf = io.BytesIO()

    with zipfile.ZipFile(in_buf, 'r') as zin:
        file_list = zin.namelist()
        with zipfile.ZipFile(out_buf, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for name in file_list:
                zout.writestr(name, zin.read(name))
            zout.comment = payload

    out_buf.seek(0)
    return out_buf.getvalue(), {
        "chars": len(secret),
        "payload_bytes": len(payload),
        "files_in_zip": len(file_list),
        "method": "ZIP Comment"
    }

def decode_zip(zip_bytes: bytes, password: str) -> str:
    in_buf = io.BytesIO(zip_bytes)
    with zipfile.ZipFile(in_buf, 'r') as zf:
        comment = zf.comment
    if not comment:
        raise ValueError("ZIP файлд нууц мэдээлэл олдсонгүй.")
    try:
        text = comment.decode("utf-8")
    except Exception:
        raise ValueError("ZIP comment уншиж чадсангүй.")
    if END_MARKER not in text:
        raise ValueError("Нууц мэдээлэл олдсонгүй.")
    cipher = text.split(END_MARKER)[0]
    return decrypt_aes_gcm(cipher, password)



# 4. TAR — PAX header extension steganography

TAR_STEG_KEY = "stegocrypt.secret"

def encode_tar(tar_bytes: bytes, secret: str, password: str) -> tuple:
    cipher  = encrypt_aes_gcm(secret, password)
    payload = cipher + END_MARKER

    in_buf  = io.BytesIO(tar_bytes)
    out_buf = io.BytesIO()
    written_steg = False
    file_count = 0

    with tarfile.open(fileobj=in_buf, mode='r:*') as tin:
        with tarfile.open(fileobj=out_buf, mode='w:gz') as tout:
            for member in tin.getmembers():
                f = None
                if not member.isdir():
                    f = tin.extractfile(member)
                tout.addfile(member, f)
                file_count += 1

            # PAX global header-д нуух
            pax_info = tarfile.TarInfo(name="")
            pax_info.pax_headers = {TAR_STEG_KEY: payload}
            pax_info.type = tarfile.GNUTYPE_SPARSE
            try:
                tout.addfile(pax_info)
            except Exception:
                pass
            written_steg = True

    out_buf.seek(0)
    return out_buf.getvalue(), {
        "chars": len(secret),
        "files_in_tar": file_count,
        "method": "TAR PAX Header"
    }

def decode_tar(tar_bytes: bytes, password: str) -> str:
    in_buf = io.BytesIO(tar_bytes)
    # PAX header-аас хайна
    try:
        with tarfile.open(fileobj=in_buf, mode='r:*') as tf:
            for member in tf.getmembers():
                if member.pax_headers:
                    val = member.pax_headers.get(TAR_STEG_KEY, "")
                    if val and END_MARKER in val:
                        cipher = val.split(END_MARKER)[0]
                        return decrypt_aes_gcm(cipher, password)
    except Exception as e:
        pass
    raise ValueError("Нууц мэдээлэл олдсонгүй.")


# Routes

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/capacity", methods=["POST"])
def capacity():
    f    = request.files.get("image")
    ftype = request.form.get("type", "png")
    if not f:
        return jsonify({"error": "Файл байхгүй"}), 400
    try:
        data = f.read()
        if ftype in ("png", "bmp"):
            img = Image.open(io.BytesIO(data)).convert("RGB")
            w, h = img.size
            cap  = w * h * 3 // 8
            return jsonify({"width": w, "height": h, "capacity_bytes": cap, "method": "LSB"})
        elif ftype == "jpeg":
            img = Image.open(io.BytesIO(data))
            w, h = img.size
            # Approximate: ~0.5 AC coeff per pixel for Y channel
            cap = int(w * h * 0.5 / 8)
            return jsonify({"width": w, "height": h, "capacity_bytes": cap, "method": "DCT"})
        elif ftype == "zip":
            zf = zipfile.ZipFile(io.BytesIO(data))
            files = zf.namelist()
            return jsonify({"files": len(files), "capacity_bytes": 65535, "method": "ZIP Comment"})
        elif ftype == "tar":
            return jsonify({"capacity_bytes": 8192, "method": "TAR PAX Header"})
        elif ftype == "video":
            try:
                _require_ffmpeg()
                with tempfile.TemporaryDirectory() as tmpdir:
                    vpath = os.path.join(tmpdir, "v.tmp")
                    with open(vpath, "wb") as vf:
                        vf.write(data)
                    info = _probe_audio(vpath)
                    # samples = channels * sample_rate * duration
                    cap_samples = int(info["channels"] * info["sample_rate"] * info["duration"])
                    cap_bytes   = cap_samples // 8
                return jsonify({
                    "capacity_bytes": cap_bytes,
                    "sample_rate": info["sample_rate"],
                    "channels": info["channels"],
                    "duration": round(info["duration"], 1),
                    "method": "Video Audio LSB"
                })
            except Exception as e:
                return jsonify({"error": str(e)}), 400
        else:
            return jsonify({"error": "Тодорхойгүй төрөл"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/encode", methods=["POST"])
def encode():
    f        = request.files.get("file")
    secret   = request.form.get("secret", "")
    password = request.form.get("password", "")
    ftype    = request.form.get("type", "png")
    rand     = request.form.get("random", "false").lower() == "true"
    seed     = int(request.form.get("seed", 42))
    quality  = int(request.form.get("quality", 85))

    if not f:        return jsonify({"error": "Файл байхгүй"}), 400
    if not secret:   return jsonify({"error": "Нууц текст хоосон байна"}), 400
    if not password: return jsonify({"error": "Password оруулна уу"}), 400

    try:
        data = f.read()
        if ftype == "png":
            out_bytes, info = encode_png_lsb(data, secret, password, rand, seed)
            ext = "png"
        elif ftype == "jpeg":
            out_bytes, info = encode_jpeg_dct(data, secret, password, quality)
            ext = "jpg"
        elif ftype == "zip":
            out_bytes, info = encode_zip(data, secret, password)
            ext = "zip"
        elif ftype == "tar":
            out_bytes, info = encode_tar(data, secret, password)
            ext = "tar.gz"
        elif ftype == "video":
            out_bytes, info = encode_video_audio(data, secret, password)
            ext = "mkv"
        else:
            return jsonify({"error": "Дэмжигдээгүй формат"}), 400

        filename = f"stego_{uuid.uuid4().hex[:8]}.{ext}"
        out_path = os.path.join(OUTPUT_FOLDER, filename)
        with open(out_path, "wb") as fp:
            fp.write(out_bytes)

        return jsonify({"success": True, "filename": filename, "info": info})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/decode", methods=["POST"])
def decode():
    f        = request.files.get("file")
    password = request.form.get("password", "")
    ftype    = request.form.get("type", "png")
    rand     = request.form.get("random", "false").lower() == "true"
    seed     = int(request.form.get("seed", 42))

    if not f:        return jsonify({"error": "Файл байхгүй"}), 400
    if not password: return jsonify({"error": "Password оруулна уу"}), 400

    try:
        data = f.read()
        if ftype == "png":
            secret = decode_png_lsb(data, password, rand, seed)
        elif ftype == "jpeg":
            secret = decode_jpeg_dct(data, password)
        elif ftype == "zip":
            secret = decode_zip(data, password)
        elif ftype == "tar":
            secret = decode_tar(data, password)
        elif ftype == "video":
            secret = decode_video_audio(data, password)
        else:
            return jsonify({"error": "Дэмжигдээгүй формат"}), 400

        return jsonify({"success": True, "secret": secret, "chars": len(secret)})
    except Exception as e:
        msg = str(e)
        if not msg or "tag" in msg.lower() or "invalid" in msg.lower():
            msg = "Password буруу байна!"
        return jsonify({"error": msg}), 400


@app.route("/api/download/<filename>")
def download(filename):
    path = os.path.join(OUTPUT_FOLDER, filename)
    if not os.path.exists(path):
        return jsonify({"error": "Файл олдсонгүй"}), 404
    return send_file(path, as_attachment=True, download_name=filename)

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        "success": False,
        "error": "Файл хэт том байна. 500MB-аас бага видео оруулна уу."
    }), 413

# ══════════════════════════════════════════════════════════════════════════════
# 5. VIDEO — Audio Track PCM LSB Steganography
#    Pipeline: video → extract PCM audio (WAV) → embed in int16 samples LSB
#              → remux back into MKV container (lossless copy of video stream)
# ══════════════════════════════════════════════════════════════════════════════
import subprocess
import tempfile
import shutil

def _require_ffmpeg():
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        raise ValueError(
            "ffmpeg болон ffprobe суулгаагүй байна. "
            "`apt install ffmpeg` эсвэл `brew install ffmpeg` ажиллуулна уу."
        )

def _probe_audio(path: str) -> dict:
    """Return first audio stream info via ffprobe."""
    cmd = [
        "ffprobe", "-v", "quiet", "-print_format", "json",
        "-show_streams", "-select_streams", "a:0", path
    ]
    out = subprocess.check_output(cmd)
    import json
    data = json.loads(out)
    streams = data.get("streams", [])
    if not streams:
        raise ValueError("Видеод аудио track олдсонгүй. Дуу бүхий видео ашиглана уу.")
    s = streams[0]
    return {
        "codec":      s.get("codec_name", "pcm_s16le"),
        "channels":   int(s.get("channels", 2)),
        "sample_rate": int(s.get("sample_rate", 44100)),
        "duration":   float(s.get("duration", 0)),
    }

def _extract_wav(video_path: str, wav_path: str):
    """Extract audio as 16-bit PCM WAV."""
    cmd = [
        "ffmpeg", "-y", "-i", video_path,
        "-vn", "-acodec", "pcm_s16le", wav_path
    ]
    subprocess.run(cmd, check=True, capture_output=True)

def _remux(video_path: str, wav_path: str, out_path: str):
    """Remux original video stream + modified WAV into MKV (no re-encode)."""
    cmd = [
        "ffmpeg", "-y",
        "-i", video_path,   # original (video + original audio)
        "-i", wav_path,      # modified audio
        "-map", "0:v:0",     # video from original
        "-map", "1:a:0",     # audio from modified WAV
        "-c:v", "copy",      # video stream: lossless copy
        "-c:a", "pcm_s16le", # audio: keep as PCM (lossless)
        out_path
    ]
    subprocess.run(cmd, check=True, capture_output=True)

def encode_video_audio(video_bytes: bytes, secret: str, password: str) -> tuple:
    _require_ffmpeg()

    cipher  = encrypt_aes_gcm(secret, password)
    payload = cipher + END_MARKER
    bits    = text_to_bits(payload)
    total_bits = len(bits)

    with tempfile.TemporaryDirectory() as tmpdir:
        vid_in  = os.path.join(tmpdir, "input.mkv")
        wav_in  = os.path.join(tmpdir, "audio.wav")
        wav_out = os.path.join(tmpdir, "audio_steg.wav")
        vid_out = os.path.join(tmpdir, "output.mkv")

        with open(vid_in, "wb") as f:
            f.write(video_bytes)

        info = _probe_audio(vid_in)
        _extract_wav(vid_in, wav_in)

        # Read PCM samples as int16
        import wave
        with wave.open(wav_in, "rb") as wf:
            n_channels  = wf.getnchannels()
            sampwidth   = wf.getsampwidth()   # bytes per sample
            framerate   = wf.getframerate()
            n_frames    = wf.getnframes()
            raw_data    = wf.readframes(n_frames)

        if sampwidth != 2:
            raise ValueError(
                f"Audio sample width {sampwidth*8}-bit — 16-bit PCM шаардлагатай. "
                "ffmpeg extract алдаа байж болзошгүй."
            )

        samples = np.frombuffer(raw_data, dtype=np.int16).copy()
        capacity = len(samples)

        if total_bits > capacity:
            raise ValueError(
                f"Аудио багтаамж хүрэлцэхгүй. "
                f"Шаардлагатай: {total_bits:,} бит, "
                f"Аудио багтаамж: {capacity:,} sample (~{capacity//8:,} байт). "
                f"Урт видео ашиглана уу."
            )

        # Embed: LSB of each int16 sample
        for i, bit in enumerate(bits):
            # Preserve sign, modify only LSB of magnitude for non-zero samples
            # For zero samples: set to ±1 to avoid detectable pattern
            s = int(samples[i])
            if s == 0:
                samples[i] = np.int16(1 if int(bit) else -1) if int(bit) else np.int16(0)
            else:
                # Clear LSB and set
                samples[i] = np.int16((s & ~1) | int(bit))

        # Write modified WAV
        with wave.open(wav_out, "wb") as wf:
            wf.setnchannels(n_channels)
            wf.setsampwidth(sampwidth)
            wf.setframerate(framerate)
            wf.writeframes(samples.tobytes())

        _remux(vid_in, wav_out, vid_out)

        with open(vid_out, "rb") as f:
            out_bytes = f.read()

    used_pct = round(total_bits / capacity * 100, 4)
    return out_bytes, {
        "chars":        len(secret),
        "bits_used":    total_bits,
        "bits_total":   capacity,
        "used_pct":     used_pct,
        "sample_rate":  info["sample_rate"],
        "channels":     info["channels"],
        "method":       "Video Audio LSB"
    }


def decode_video_audio(video_bytes: bytes, password: str) -> str:
    _require_ffmpeg()

    with tempfile.TemporaryDirectory() as tmpdir:
        vid_in = os.path.join(tmpdir, "input.mkv")
        wav_in = os.path.join(tmpdir, "audio.wav")

        with open(vid_in, "wb") as f:
            f.write(video_bytes)

        _probe_audio(vid_in)   # validates audio exists
        _extract_wav(vid_in, wav_in)

        import wave
        with wave.open(wav_in, "rb") as wf:
            sampwidth = wf.getsampwidth()
            n_frames  = wf.getnframes()
            raw_data  = wf.readframes(n_frames)

        if sampwidth != 2:
            raise ValueError("16-bit PCM аудио шаардлагатай.")

        samples = np.frombuffer(raw_data, dtype=np.int16)

        bits = ""
        text = ""
        for i in range(len(samples)):
            s = int(samples[i])
            bits += str(abs(s) & 1)
            if len(bits) % 8 == 0:
                ch = chr(int(bits[-8:], 2))
                text += ch
                if END_MARKER in text:
                    cipher = text.split(END_MARKER)[0]
                    return decrypt_aes_gcm(cipher, password)
            if len(bits) > 8_000_000:   # 1MB payload хязгаар
                break

    raise ValueError("Нууц мэдээлэл олдсонгүй.")


if __name__ == "__main__":
    app.run(debug=True, port=5000)