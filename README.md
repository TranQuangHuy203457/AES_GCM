## Build
- Toolchain: MinGW-w64 (gcc/g++). Example (run from repo root):
  - `g++ -std=c++17 src/main.cpp src/AES_256.cpp src/GCM.cpp src/GMAC.cpp -o out/gcm.exe -mwindows -lgdi32 -lole32 -lshell32 -luuid -lcomdlg32 -lgdiplus -lbcrypt`
- Sources: trong `src/` (`main.cpp`, `AES_256.cpp/.h`, `GCM.cpp/.h`, `GMAC.cpp/.h`).
- No external dependencies beyond Win32/GDI+/bcrypt (Windows API).

## Run
- Launch `out/gcm.exe` (GUI) từ repo root hoặc chạy bên trong thư mục `out/`.
- Steps:
  1) Nhap KEY (DEC hoac HEX hoặc `pass:...`).
  2) Chon file Input.
  3) Chon file chu ky (AAD).
  4) Bam "Ma hoa + Tao TAG".
- Ket qua (ghi trong thư mục hiện tại của `gcm.exe`, mac dinh `out/`):
  - `cipher_output.bin`: prefix IV||cipher, va neu dung passphrase thi prefix Salt||IV||cipher.
  - `tag_output.bin`: 16 byte TAG.
  - `tag_output.txt`: TAG hex + Base64, IV (và Salt nếu có), thong tin PBKDF.
  - Status: cipher size, IV, TAG hex + Base64 (và Salt nếu có).

## Key / passphrase rules
- Nhập dạng hex/dec: nếu chỉ chứa 0-9 thì coi là DEC → đổi HEX → pad/trim 32 byte (64 hex). Nếu có ký tự hex khác → coi là HEX.
- Nhập passphrase với PBKDF2: dùng tiền tố `pass:` (vd `pass:my secret`). Chương trình sẽ sinh Salt 16 byte ngẫu nhiên, PBKDF2-HMAC-SHA256 100k vòng → khóa 32 byte. Salt được lưu vào đầu `cipher_output.bin` cùng IV.
- Ví dụ:
  - `10` → decimal 10 → HEX `0A` → pad 64 hex ký tự.
  - `0x10` hoặc `10a` → hiểu là HEX.
  - `pass:hello world` → dùng PBKDF2 với Salt ngẫu nhiên.

## Files / structure
- `src/`: `main.cpp` (Win32 GUI), `AES_256.*`, `GCM.*`, `GMAC.*`.
- `docs/`: `GCM_Report.md` (mô tả kỹ thuật).
- `out/`: binary build và file sinh ra (`gcm.exe`, cipher/tag outputs).
- `README.md`: hướng dẫn nhanh.

## Output format
- `cipher_output.bin`: nếu dùng khóa thô → `IV(12)||ciphertext`; nếu dùng passphrase → `Salt(16)||IV(12)||ciphertext`.
- `tag_output.bin`: 16 byte TAG.
- `tag_output.txt`: TAG hex, TAG Base64, IV (và Salt nếu có), thông tin PBKDF.

## Notes
- IV nay sinh ngẫu nhiên 12 byte mỗi lần và được lưu kèm (prefix file).
- Salt sinh ngẫu nhiên (nếu dùng passphrase) và lưu cùng IV.
- TAG dài 128 bit, không rút ngắn.
- Status không hiển thị preview ciphertext để tránh rò rỉ thêm.

