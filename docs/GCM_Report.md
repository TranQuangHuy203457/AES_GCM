## Tong quan AES-GCM
- AES-GCM la mode authenticated encryption: cung luc bao mat tinh bao mat (confidentiality) va toan ven (integrity + authenticity).
- Thanh phan chinh:
  - AES-CTR de ma hoa/ giai ma.
  - GHASH tren truong GF(2^128) de tinh MAC (TAG).
- Dau ra: ciphertext + TAG (MAC). TAG khong ma hoa plaintext ma la chung nhan toan ven/AAD.

## Quy trinh ma hoa
1) Dau vao: khoa 256-bit, IV 96-bit (12 byte), plaintext P, AAD (chu ky) A.
2) Keystream: dung AES-CTR voi counter bat dau tu `IV || 0x00000001`.
3) Ciphertext C = P XOR keystream.
4) GHASH tren (A, C, len(A), len(C)) tao ra gia tri S.
5) TAG = AES_k(IV || 0x00000000) XOR S (128 bit).

## Quy trinh giai ma/kiem tra
1) Tinh lai GHASH tu AAD va ciphertext.
2) Tinh TAG_kiemtra = AES_k(IV || 0x00000000) XOR S.
3) So sanh TAG_kiemtra voi TAG nhan duoc (so sanh hang so thoi gian). Khop thi giai ma, khong khop thi bao loi/bo qua ciphertext.

## Lua chon trong du an
- Khoa: 256 bit (AES-256).
- IV: 12 byte sinh ngau nhien moi lan ma hoa, luu prefix vao file.
- TAG: 128 bit khong cat ngan.
- AAD: file chu ky do nguoi dung cung cap.
- PBKDF2 tuy chon: neu nhap `pass:<passphrase>` thi dung PBKDF2-HMAC-SHA256 100k vong, salt 16 byte ngau nhien (salt duoc luu prefix).
- Xuat:
  - `cipher_output.bin`: IV||cipher (khoa thô) hoac Salt||IV||cipher (PBKDF2).
  - `tag_output.bin`: 16 byte TAG.
  - `tag_output.txt`: TAG hex, TAG Base64, IV, (Salt neu co), thong tin PBKDF.

## Ranh gioi va canh bao an toan
- IV phai duy nhat cho moi khoa/lan ma hoa. Da sinh IV 96-bit ngau nhien va prefix vao file, nhung can bao dam khong tai su dung IV khi giai ma/ghi de.
- Khong dung GCM trong che do streaming vo han ma khong quan ly IV va counter (tranh tran counter).
- Dung so sanh TAG hang so thoi gian de tranh side-channel (da ap dung trong GCM.cpp neu co).
- AAD can duoc xac dinh ro y nghia (metadata) va duoc bao dam dong nhat khi giai ma.

## Trien khai trong du an
- Sinh khoa: nhap hex/dec → chuan hoa 32 byte; nhap `pass:<passphrase>` → PBKDF2-HMAC-SHA256 100k, salt 16 byte ngau nhien.
- IV: 12 byte ngau nhien moi lan, prefix vao ciphertext file.
- TAG: 128 bit, luu rieng file bin + xuat text.
- AAD: tu file chu ky do nguoi dung chon.
- File dau ra:
  - `cipher_output.bin`: [Salt (16, neu PBKDF2)] || IV (12) || ciphertext.
  - `tag_output.bin`: TAG 16 byte.
  - `tag_output.txt`: TAG hex/Base64, IV hex, Salt hex (neu co), thong tin PBKDF, kich thuoc ciphertext.
- GUI status: hien cipher size, IV, TAG hex/Base64, Salt (neu co).

## Su dung nhanh (ma hoa)
1) Nhap KEY: 
   - Khoa thô hex/dec, hoac `pass:<passphrase>` de dung PBKDF2 (100k, salt 16 byte).
2) Chon file du lieu va file chu ky (AAD).
3) Bam "Ma hoa + Tao TAG" → sinh `cipher_output.bin`, `tag_output.bin`, `tag_output.txt`.





