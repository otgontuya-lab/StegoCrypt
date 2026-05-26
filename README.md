# StegoCrypt v3.0

AES-256-GCM шифрлэлттэй multi-format steganography хэрэгсэл.

## Дэмжигдэх форматууд

| Формат | Арга | Тайлбар |
|--------|------|---------|
| PNG/BMP | LSB | Pixel-ийн хамгийн доод битэд нуух |
| JPEG | DCT | AC коэффициентийн LSB-д нуух (F5-style) |
| ZIP | Comment | End-of-Central-Directory comment талбарт нуух |
| TAR | PAX Header | PAX extension header-т нуух |

## Суулгах

```bash
pip install flask cryptography pillow numpy scipy
python app.py
```

## Шаардлага

- Python 3.10+
- flask, cryptography, pillow, numpy, scipy
