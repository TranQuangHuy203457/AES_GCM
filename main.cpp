#include <windows.h>
#include <shobjidl.h>
#include <commdlg.h>
#include <gdiplus.h>
#include <bcrypt.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <limits>

#pragma comment(lib, "bcrypt")


#include "AES_256.h"
#include "GCM.h"
#include "GMAC.h"

// =============================================
// Utility: convert hex string → bytes
// =============================================
std::vector<uint8_t> hexToBytes(const std::string& hex)
{
    std::vector<uint8_t> out;
    if (hex.size() % 2 != 0) return out;

    for (size_t i = 0; i < hex.size(); i += 2)
    {
        uint8_t b = std::stoi(hex.substr(i, 2), nullptr, 16);
        out.push_back(b);
    }
    return out;
}

// =============================================
// Convert big decimal string → hex string
// Implement big integer div-by-16 manually
// =============================================

std::string decToHex(const std::string& decStr)
{
    std::string num = decStr;
    std::string hex = "";
    const char* HEX = "0123456789ABCDEF";

    while (!(num.size() == 1 && num[0] == '0')) {
        int carry = 0;
        std::string next = "";

        for (char c : num) {
            int cur = carry * 10 + (c - '0');
            int q = cur / 16;
            carry = cur % 16;

            if (!(next.empty() && q == 0))
                next.push_back('0' + q);
        }

        hex.push_back(HEX[carry]);

        if (next.empty()) next = "0";
        num = next;
    }

    std::reverse(hex.begin(), hex.end());
    return hex;
}

// Base64 encode (simple, for small buffers like TAG)
std::string toBase64(const std::vector<uint8_t>& data)
{
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back(tbl[n & 63]);
        i += 3;
    }
    if (i + 1 < data.size()) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back('=');
    } else if (i < data.size()) {
        uint32_t n = (data[i] << 16);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    }
    return out;
}

std::string bytesToHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setw(2) << std::setfill('0');
    for (auto b : data) oss << (int)b;
    return oss.str();
}

// Cryptographically strong random bytes (system RNG)
std::vector<uint8_t> randomBytes(size_t n)
{
    std::vector<uint8_t> buf(n);
    if (n == 0) return buf;
    NTSTATUS st = BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) return {};
    return buf;
}

// PBKDF2-HMAC-SHA256 to derive 32-byte key from passphrase + salt
std::vector<uint8_t> deriveKeyPBKDF2(const std::string& pass, const std::vector<uint8_t>& salt, ULONG iterations = 100000)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return {};

    std::vector<uint8_t> out(32, 0);
    st = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)pass.data(), (ULONG)pass.size(),
        (PUCHAR)salt.data(), (ULONG)salt.size(),
        iterations,
        out.data(), (ULONG)out.size(),
        0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (!BCRYPT_SUCCESS(st)) return {};
    return out;
}


// =============================================
// Auto-detect DEC or HEX input → convert to 32-byte key
// =============================================
std::vector<uint8_t> normalizeKey(std::string keyIn)
{
    bool isDecimal = std::all_of(keyIn.begin(), keyIn.end(), ::isdigit);

    std::string hex;

    if (isDecimal)
    {
        std::cout << "Detected DEC → converting to HEX...\n";
        hex = decToHex(keyIn);
    }
    else
    {
        std::cout << "Detected HEX input\n";
        hex = keyIn;
    }

    // Remove spaces
    hex.erase(std::remove(hex.begin(), hex.end(), ' '), hex.end());

    // Pad or trim to 32 bytes (64 hex chars)
    if (hex.size() < 64)
    {
        hex.insert(hex.begin(), 64 - hex.size(), '0');
    }
    else if (hex.size() > 64)
    {
        hex = hex.substr(hex.size() - 64);
    }

    return hexToBytes(hex);
}

// -----------------------------------------------
// Select a file and return its path (UTF-8)
std::string pickFilePath()
{
    IFileDialog* pfd = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&pfd));
    if (FAILED(hr)) {
        return {};
    }

    hr = pfd->Show(NULL);
    if (FAILED(hr)) {
        return {};
    }

    IShellItem* psi;
    hr = pfd->GetResult(&psi);
    if (FAILED(hr)) {
        pfd->Release();
        return {};
    }

    PWSTR pszFilePath;
    psi->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

    std::wstring ws(pszFilePath);
    std::string path(ws.begin(), ws.end());
    CoTaskMemFree(pszFilePath);
    psi->Release();
    pfd->Release();
    return path;
}

std::vector<uint8_t> readFileBytes(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), {});
}

// =================================================================
// SIMPLE GUI (Win32)
// =================================================================

namespace {
    HWND g_hEditKey = nullptr;
    HWND g_hStatus = nullptr;
    HWND g_hDataLabel = nullptr;
    HWND g_hSigLabel = nullptr;
    RECT g_dataRect{20, 110, 480, 300};
    RECT g_sigRect{520, 110, 980, 300};
    Gdiplus::Bitmap* g_imgData = nullptr;
    Gdiplus::Bitmap* g_imgSig = nullptr;
    ULONG_PTR g_gdiplusToken = 0;
    std::string g_dataPath;
    std::string g_sigPath;

    void SetStatus(const std::string& text) {
        if (!g_hStatus) return;
        std::wstring ws(text.begin(), text.end());
        SendMessageW(g_hStatus, WM_SETTEXT, 0, (LPARAM)ws.c_str());
    }

    void AppendStatus(const std::string& line) {
        if (!g_hStatus) return;
        int len = GetWindowTextLengthW(g_hStatus);
        SendMessageW(g_hStatus, EM_SETSEL, len, len);
        std::wstring ws(line.begin(), line.end());
        SendMessageW(g_hStatus, EM_REPLACESEL, FALSE, (LPARAM)ws.c_str());
    }

    void updatePathLabels() {
        if (g_hDataLabel) {
            std::wstring ws(g_dataPath.begin(), g_dataPath.end());
            SendMessageW(g_hDataLabel, WM_SETTEXT, 0, (LPARAM)ws.c_str());
        }
        if (g_hSigLabel) {
            std::wstring ws(g_sigPath.begin(), g_sigPath.end());
            SendMessageW(g_hSigLabel, WM_SETTEXT, 0, (LPARAM)ws.c_str());
        }
    }

    void loadPreviewImage(const std::string& path, Gdiplus::Bitmap*& targetImg) {
        if (targetImg) {
            delete targetImg;
            targetImg = nullptr;
        }
        std::wstring ws(path.begin(), path.end());
        Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromFile(ws.c_str(), FALSE);
        if (bmp && bmp->GetLastStatus() == Gdiplus::Ok) {
            targetImg = bmp;
        } else {
            if (bmp) delete bmp;
            targetImg = nullptr;
        }
    }

    void doEncryptGUI() {
        char keyBuf[256] = {0};
        GetWindowTextA(g_hEditKey, keyBuf, sizeof(keyBuf));
        std::string key_in(keyBuf);

        if (key_in.empty()) {
            MessageBoxW(NULL, L"Vui long nhap KEY", L"Thong bao", MB_ICONWARNING);
            return;
        }
        if (g_dataPath.empty() || g_sigPath.empty()) {
            MessageBoxW(NULL, L"Input va Chữ ký", L"Thong bao", MB_ICONWARNING);
            return;
        }

        AppendStatus("Dang doc file...\r\n");
        auto plaintext = readFileBytes(g_dataPath);
        auto signature = readFileBytes(g_sigPath);
        if (plaintext.empty() || signature.empty()) {
            AppendStatus("[LOI] Khong the doc file.\r\n");
            MessageBoxW(NULL, L"Doc file that bai", L"Loi", MB_ICONERROR);
            return;
        }

        bool usePBKDF = false;
        std::vector<uint8_t> salt;
        std::vector<uint8_t> key;

        if (key_in.rfind("pass:", 0) == 0 || key_in.rfind("PASS:", 0) == 0 || key_in.rfind("Pass:", 0) == 0) {
            usePBKDF = true;
            std::string passphrase = key_in.substr(5);
            salt = randomBytes(16);
            if (salt.empty()) {
                AppendStatus("[LOI] Khong the tao salt ngau nhien.\r\n");
                MessageBoxW(NULL, L"Tao salt that bai", L"Loi", MB_ICONERROR);
                return;
            }
            key = deriveKeyPBKDF2(passphrase, salt, 100000);
            if (key.empty()) {
                AppendStatus("[LOI] PBKDF2 that bai.\r\n");
                MessageBoxW(NULL, L"PBKDF2 that bai", L"Loi", MB_ICONERROR);
                return;
            }
            AppendStatus("PBKDF2-HMAC-SHA256 (100k) tu passphrase.\r\n");
        } else {
            key = normalizeKey(key_in);
            AppendStatus("Key OK (hex/dec). Dang ma hoa...\r\n");
        }

        auto iv = randomBytes(12);
        if (iv.empty()) {
            AppendStatus("[LOI] Khong the tao IV ngau nhien.\r\n");
            MessageBoxW(NULL, L"Tao IV that bai", L"Loi", MB_ICONERROR);
            return;
        }

        AES256_GCM gcm(key);
        std::vector<uint8_t> tag_encrypt;

        auto ciphertext = gcm.Encrypt(iv, plaintext, signature, tag_encrypt);

        try {
            auto decrypted = gcm.Decrypt(iv, ciphertext, signature, tag_encrypt);
            (void)decrypted;
        } catch (...) {
            AppendStatus("[LOI] TAG khong hop le sau khi ma hoa?!\r\n");
            MessageBoxW(NULL, L"TAG khong hop le", L"Loi", MB_ICONERROR);
            return;
        }

        std::ofstream fout("cipher_output.bin", std::ios::binary);
        if (!fout) {
            AppendStatus("[LOI] Khong the mo cipher_output.bin de ghi.\r\n");
            MessageBoxW(NULL, L"Ghi file that bai", L"Loi", MB_ICONERROR);
            return;
        }
        if (usePBKDF) {
            fout.write((char*)salt.data(), salt.size()); // prefix SALT
        }
        fout.write((char*)iv.data(), iv.size()); // prefix IV
        fout.write((char*)ciphertext.data(), ciphertext.size());

        std::ofstream ftag("tag_output.bin", std::ios::binary);
        if (ftag) ftag.write((char*)tag_encrypt.data(), tag_encrypt.size());

        std::ofstream ftagTxt("tag_output.txt");
        if (ftagTxt) {
            ftagTxt << "TAG (hex): " << bytesToHex(tag_encrypt) << "\n";
            ftagTxt << "TAG (Base64): " << toBase64(tag_encrypt) << "\n";
            ftagTxt << "IV (hex): " << bytesToHex(iv) << "\n";
            if (usePBKDF) {
                ftagTxt << "Salt (hex): " << bytesToHex(salt) << "\n";
                ftagTxt << "PBKDF2: HMAC-SHA256, 100000 vong\n";
            }
            ftagTxt << "Cipher bytes: " << ciphertext.size() << "\n";
        }

        std::ostringstream oss;
        oss << "Cipher: " << ciphertext.size() << " bytes\r\n";
        oss << "IV (hex): " << bytesToHex(iv) << "\r\n";
        if (usePBKDF) {
            oss << "Salt (hex): " << bytesToHex(salt) << " (PBKDF2-HMAC-SHA256, 100k)\r\n";
        }
        oss << "Tag (hex): " << bytesToHex(tag_encrypt) << "\r\n";
        oss << "Tag (Base64): " << toBase64(tag_encrypt) << "\r\n";
        if (usePBKDF) {
            oss << "Da luu: cipher_output.bin (salt||IV||cipher), tag_output.bin, tag_output.txt\r\n";
        } else {
            oss << "Da luu: cipher_output.bin (IV||cipher), tag_output.bin, tag_output.txt\r\n";
        }
        AppendStatus(oss.str());
        MessageBoxW(NULL, L"Hoan thanh! Da luu cipher_output.bin, tag_output.bin, tag_output.txt", L"Thong bao", MB_OK | MB_ICONINFORMATION);
    }

    LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_CREATE: {
            CreateWindowW(L"STATIC", L"KEY (DEC/HEX):", WS_VISIBLE | WS_CHILD, 20, 20, 120, 20, hWnd, NULL, NULL, NULL);
            g_hEditKey = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 140, 20, 300, 24, hWnd, (HMENU)1, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Chon Input", WS_VISIBLE | WS_CHILD, 60, 50, 180, 28, hWnd, (HMENU)1001, NULL, NULL);
            g_hDataLabel = CreateWindowW(L"STATIC", L"(chua chon)", WS_VISIBLE | WS_CHILD, 60, 85, 220, 20, hWnd, NULL, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Ma hoa + Tao TAG", WS_VISIBLE | WS_CHILD, 380, 50, 180, 32, hWnd, (HMENU)1003, NULL, NULL);

            CreateWindowW(L"BUTTON", L"Chọn Chữ Ký", WS_VISIBLE | WS_CHILD, 700, 50, 180, 28, hWnd, (HMENU)1002, NULL, NULL);
            g_hSigLabel = CreateWindowW(L"STATIC", L"(chua chon)", WS_VISIBLE | WS_CHILD, 700, 85, 220, 20, hWnd, NULL, NULL, NULL);

            g_hStatus = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                       20, 320, 580, 200, hWnd, NULL, NULL, NULL);
            SetStatus("San sang. Nhap KEY, chon file du lieu va chu ky.\r\n");
            break;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            Rectangle(hdc, g_dataRect.left - 2, g_dataRect.top - 2, g_dataRect.right + 2, g_dataRect.bottom + 2);
            Rectangle(hdc, g_sigRect.left - 2, g_sigRect.top - 2, g_sigRect.right + 2, g_sigRect.bottom + 2);

            if (g_imgData) {
                Gdiplus::Graphics g(hdc);
                g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                g.DrawImage(g_imgData, (Gdiplus::REAL)g_dataRect.left, (Gdiplus::REAL)g_dataRect.top,
                            (Gdiplus::REAL)(g_dataRect.right - g_dataRect.left),
                            (Gdiplus::REAL)(g_dataRect.bottom - g_dataRect.top));
            }

            if (g_imgSig) {
                Gdiplus::Graphics g(hdc);
                g.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
                g.DrawImage(g_imgSig, (Gdiplus::REAL)g_sigRect.left, (Gdiplus::REAL)g_sigRect.top,
                            (Gdiplus::REAL)(g_sigRect.right - g_sigRect.left),
                            (Gdiplus::REAL)(g_sigRect.bottom - g_sigRect.top));
            }
            EndPaint(hWnd, &ps);
            break;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
            case 1001: {
                g_dataPath = pickFilePath();
                updatePathLabels();
                if (!g_dataPath.empty()) {
                    loadPreviewImage(g_dataPath, g_imgData);
                    InvalidateRect(hWnd, &g_dataRect, TRUE);
                }
                break;
            }
            case 1002: {
                g_sigPath = pickFilePath();
                updatePathLabels();
                if (!g_sigPath.empty()) {
                    loadPreviewImage(g_sigPath, g_imgSig);
                    InvalidateRect(hWnd, &g_sigRect, TRUE);
                }
                break;
            }
            case 1003: {
                doEncryptGUI();
                break;
            }
            default:
                break;
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
        }
        return 0;
    }
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    if (Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL) != Gdiplus::Ok) {
        CoUninitialize();
        return 0;
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"GCMGuiWnd";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClassW(&wc)) return 0;

    HWND hWnd = CreateWindowW(L"GCMGuiWnd", L"AES-256 GCM GUI", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                              CW_USEDEFAULT, CW_USEDEFAULT, 1040, 620, NULL, NULL, hInstance, NULL);
    if (!hWnd) return 0;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    if (g_imgData) delete g_imgData;
    if (g_imgSig) delete g_imgSig;
    if (g_gdiplusToken) Gdiplus::GdiplusShutdown(g_gdiplusToken);
    CoUninitialize();
    return (int)msg.wParam;
}
