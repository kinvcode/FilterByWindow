#ifndef MSGFILTERWINDOW_H
#define MSGFILTERWINDOW_H

#include <QDialog>
#include <vector>
#include "drv/PeaceDriverAPI.h"

constexpr UINT WM_MY_CUSTOM_MESSAGE = WM_USER + 100;
constexpr ULONG64 kHookCodeSize = 13;

namespace Ui {
class MsgFilterWindow;
}

template <typename Fn>
inline void for_each_cpu(Fn const fn) {
    SYSTEM_INFO info = {};
    GetSystemInfo(&info);

    for (uint32_t i = 0; i < info.dwNumberOfProcessors; ++i) {
        auto const prev_affinity = SetThreadAffinityMask(GetCurrentThread(), 1ull << i);
        fn(i);
        SetThreadAffinityMask(GetCurrentThread(), prev_affinity);
    }
}

inline std::vector<byte> operator+(std::vector<byte> a, std::vector<byte> b)
{
    for (int i = 0; i < b.size(); i++)
    {
        a.push_back(b[i]);
    }

    b.clear();

    return a;
}

inline std::vector<byte> intToBytes(int length)
{
    __int64  adr = (__int64)&length;
    std::vector<byte>c;
    for (size_t i = 0; i < 4; i++) {
        c.push_back(*(byte*)adr++);
    }
    return c;
}

inline std::vector<byte> longToBytes(long long length)
{
    __int64  adr = (__int64)&length;
    std::vector<byte>c;
    for (size_t i = 0; i < 8; i++) {
        c.push_back(*(byte*)adr++);
    }
    return c;
}

inline std::vector<byte> makeByteArray(std::vector<byte> data)
{
    return data;
}

class MsgFilterWindow : public QDialog
{
    Q_OBJECT

public:
    explicit MsgFilterWindow(QWidget *parent = nullptr);
    ~MsgFilterWindow() override;

protected:
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result) override;

private slots:
    void on_pushButton_startHook_clicked();

    void on_pushButton_destroyWindow_clicked();

private:
    Ui::MsgFilterWindow *ui;

    struct HOOKDATA{
        bool is_hooked = false;
        DWORD pid = 0;
        ULONG64 hook_address = 0;
        ULONG64 allocated_address = 0;
        ULONG64 shadowpage_address = 0;
        uint64_t hook_pfn = 0;
        BYTE raw_bytecode[kHookCodeSize] = {0};
    }_hook_data;

    bool hook(DWORD pid);
    bool unhook();
};

#endif // MSGFILTERWINDOW_H
