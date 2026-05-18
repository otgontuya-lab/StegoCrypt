# StegoCrypt

StegoCrypt нь AES-256-GCM шифрлэлт болон LSB steganography ашиглан нууц текст мэдээллийг PNG зураг дотор нуух, буцаан тайлах программ юм.

## Төслийн зорилго

Энэхүү төслийн зорилго нь нууц мэдээллийг password ашиглан шифрлэж, PNG зурагны pixel-ийн LSB bit-д нуух замаар мэдээллийн аюулгүй байдлыг хангах юм.

## Ашигласан технологи

- Python
- Tkinter
- Pillow
- cryptography
- AES-256-GCM
- LSB Steganography

## Үндсэн боломжууд

- PNG зураг дотор нууц текст нуух
- Password ашиглан AES-256-GCM шифрлэх
- LSB аргаар мэдээлэл нуух
- Random embedding болон seed ашиглах
- Decode хийж нууц текстийг буцаан гаргах

## Ажиллуулах заавар

```bash
pip install -r requirements.txt
python final.py
