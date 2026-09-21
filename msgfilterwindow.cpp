#include "msgfilterwindow.h"
#include "ui_msgfilterwindow.h"
#include "drv/PeaceDriverAPI.h"

#include <QDateTime>
#include <QHeaderView>
#include <QMessageBox>
#include <QTableWidgetItem>
#include <cstring>
#include <limits>
#include <memory>

namespace {
constexpr ULONG64 kRemoteBufferSize = 0x1000;

bool isExecutableProtection(ULONG protection)
{
    if ((protection & PAGE_GUARD) != 0) {
        return false;
    }

    switch (protection & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}
}

MsgFilterWindow::MsgFilterWindow(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::MsgFilterWindow)
{
    ui->setupUi(this);
    ui->tableWidget_msgList->setColumnCount(2);
    ui->tableWidget_msgList->setHorizontalHeaderLabels({tr("时间"), tr("数据指针")});
    ui->tableWidget_msgList->horizontalHeader()->setStretchLastSection(true);
}

MsgFilterWindow::~MsgFilterWindow()
{
    if (!unhook()) {
        qWarning() << "窗口销毁时清理HOOK失败";
    }
    delete ui;
}


bool MsgFilterWindow::hook(DWORD pid, ULONG64 hook_address)
{
    ULONG64 shadowpage_address = 0;
    ULONG64 asmcode_address = 0;
    uint64_t hook_pfn = 0;
    bool ept_installed = false;

    const auto cleanupPartial = [&]() {
        if (ept_installed && hook_pfn != 0) {
            remove_ept_hook(hook_pfn);
            ept_installed = false;
        }
        if (asmcode_address != 0) {
            freeMemory(pid, asmcode_address);
            asmcode_address = 0;
        }
        if (shadowpage_address != 0) {
            freeMemory(pid, shadowpage_address);
            shadowpage_address = 0;
        }
    };

    // 找出目标进程，user32模块PostMessageA函数地址
    const ULONG64 moduleBase = getModuleBase(pid, L"user32.dll");
    if(moduleBase == 0){
        qDebug() << "模块基址未找到";
        return false;
    }

    const ULONG64 PostMessageA = getModuleExport(pid, moduleBase, "PostMessageA");
    if(PostMessageA == 0){
        qDebug() << "PostMessageA基址未找到";
        return false;
    }

    // 计算HOOK页面的地址和hook位置偏移
    uintptr_t hook_page_start  = hook_address & ~0xFFF;
    void*     hook_page_ptr    = reinterpret_cast<void*>(hook_page_start);
    uintptr_t hook_offset      = hook_address - reinterpret_cast<uintptr_t>(hook_page_ptr);
    qDebug() << "HOOK页面起始地址：" << QString::number((uint64_t)hook_page_ptr,16).toUpper();
    qDebug() << "HOOK函数偏移："    << QString::number((uint64_t)hook_offset,16).toUpper();

    // 读取目标程序CR3
    ULONG64 target_cr3 = query_process_cr3(pid);
    if(!target_cr3){
        qDebug() << "cr3查询失败";
        return false;
    }

    if ((target_cr3 & 0xFFF) != 0) {
        qDebug() << "CR3值无效（未页对齐）：" << QString::number(target_cr3,16).toUpper();
        return false;
    }

    // 获取HOOK页面的物理地址（使用页面对齐的地址）
    uint64_t hook_phys_addr = get_physical_address(target_cr3, hook_page_ptr);
    if (!hook_phys_addr) {
        qDebug() << "无法获取HOOK物理页，后续操作中断";
        return false;
    }
    qDebug() << "HOOK物理地址：" << QString::number(hook_phys_addr,16).toUpper();

    hook_pfn = hook_phys_addr >> 12;
    qDebug() << "HOOK物理页帧号(PFN)：" << QString::number(hook_pfn,16).toUpper();

    // 在目标进程中申请一段内存，作为影子页
    shadowpage_address = allocMemory(pid, kRemoteBufferSize);
    if(shadowpage_address == 0){
        qDebug() << "申请影子内存失败";
        return false;
    }

    qDebug() << "申请影子空间：" << QString::number(shadowpage_address,16).toUpper();

    // 复制数据到影子页
    auto hook_page_cache = std::make_unique<byte[]>(0x1000);
    if (!readMemory(pid, reinterpret_cast<uint64_t>(hook_page_ptr), 0x1000, hook_page_cache.get())) {
        qDebug() << "读取HOOK页面失败";
        cleanupPartial();
        return false;
    }

    qDebug() << "准备复制页面数据";
    if (!writeMemory(pid, shadowpage_address, 0x1000, hook_page_cache.get())) {
        qDebug() << "写入影子页失败";
        cleanupPartial();
        return false;
    }

    // 获取影子页的物理帧
    uint64_t shadow_phys_addr = get_physical_address(target_cr3, reinterpret_cast<void*>(shadowpage_address));
    if (!shadow_phys_addr) {
        qDebug() << "无法获取影子页物理地址，后续操作中断";
        cleanupPartial();
        return false;
    }
    qDebug() << "影子页物理地址：" << QString::number(shadow_phys_addr,16).toUpper();
    uint64_t shadow_pfn = shadow_phys_addr >> 12;
    qDebug() << "影子页物理页帧号(PFN)：" << QString::number(shadow_pfn,16).toUpper();

    // 创建汇编函数执行页
    // 在目标进程中申请一段内存
    asmcode_address = allocMemory(pid, 0x1000);
    if(asmcode_address == 0){
        qDebug() << "申请汇编内存失败";
        cleanupPartial();
        return false;
    }

    qDebug() << "申请汇编空间：" << QString::number(asmcode_address,16).toUpper();

    // 需要保存HOOK位置原始字节码
    BYTE raw_bytecode[kHookCodeSize] = {0};
    const bool read_res = readMemory(pid, hook_address, kHookCodeSize, raw_bytecode);
    if(!read_res){
        qDebug() << "读取HOOK原始字节码失败";
        cleanupPartial();
        return false;
    }

    // 转字节容器
    std::vector<byte> raw_bytearray;
    raw_bytearray.resize(kHookCodeSize);
    for (int i = 0; i < kHookCodeSize; i++)
    {
        raw_bytearray[i] = raw_bytecode[i];
    }

    // 获取本窗口句柄
    HWND hwnd = reinterpret_cast<HWND>(this->winId());
    UINT_PTR my_window_handle = reinterpret_cast<UINT_PTR>(hwnd);

    // 构造PostMessageA函数汇编

    std::vector<byte>asmData;
    asmData = makeByteArray({0x50});                    // push rax
    asmData = asmData + makeByteArray({0x53});          // push rbx
    asmData = asmData + makeByteArray({0x51});          // push rcx
    asmData = asmData + makeByteArray({0x52});          // push rdx
    asmData = asmData + makeByteArray({0x56});          // push rsi
    asmData = asmData + makeByteArray({0x57});          // push rdi
    asmData = asmData + makeByteArray({0x41, 0x50});    // push r8
    asmData = asmData + makeByteArray({0x41, 0x51});    // push r9
    asmData = asmData + makeByteArray({0x41, 0x52});    // push r10
    asmData = asmData + makeByteArray({0x41, 0x53});    // push r11
    asmData = asmData + makeByteArray({0x41, 0x54});    // push r12
    asmData = asmData + makeByteArray({0x41, 0x55});    // push r13
    asmData = asmData + makeByteArray({0x41, 0x56});    // push r14
    asmData = asmData + makeByteArray({0x41, 0x57});    // push r15
    asmData = asmData + makeByteArray({0x48, 0x83, 0xEC, 0x28});                            // sub rsp,0x28
    asmData = asmData + makeByteArray({0x48, 0xB9}) + longToBytes(my_window_handle);        // mov rcx,窗口句柄
    asmData = asmData + makeByteArray({0x48, 0xBA}) + longToBytes(WM_MY_CUSTOM_MESSAGE);    // mov rcx,消息类型
    asmData = asmData + makeByteArray({0x4D, 0x8B, 0xC8});                                  // mov r9, r8 // 数据指针传给参数3
    asmData = asmData + makeByteArray({0x4D, 0x31, 0xC0});                                  // xor r8, r8
    asmData = asmData + makeByteArray({0x48, 0xB8}) + longToBytes(PostMessageA);            // mov rax, PostMessageA
    asmData = asmData + makeByteArray({0xFF, 0xD0});                                        // call rax
    asmData = asmData + makeByteArray({0x48, 0x83, 0xC4, 0x28});                            // add rsp, 0x28
    asmData = asmData + makeByteArray({0x41, 0x5F});    // pop r15
    asmData = asmData + makeByteArray({0x41, 0x5E});    // pop r14
    asmData = asmData + makeByteArray({0x41, 0x5D});    // pop r13
    asmData = asmData + makeByteArray({0x41, 0x5C});    // pop r12
    asmData = asmData + makeByteArray({0x41, 0x5B});    // pop r11
    asmData = asmData + makeByteArray({0x41, 0x5A});    // pop r10
    asmData = asmData + makeByteArray({0x41, 0x59});    // pop r9
    asmData = asmData + makeByteArray({0x41, 0x58});    // pop r8
    asmData = asmData + makeByteArray({0x5F});          // pop rdi
    asmData = asmData + makeByteArray({0x5E});          // pop rsi
    asmData = asmData + makeByteArray({0x5A});          // pop rdx
    asmData = asmData + makeByteArray({0x59});          // pop rcx
    asmData = asmData + makeByteArray({0x5B});          // pop rbx
    asmData = asmData + makeByteArray({0x58});          // pop rax

    // 加上HOOK函数代码，注意修复地址：48 BA C0 4E C8 41 F6 7F 00 00
    asmData = asmData + makeByteArray({0x41,0xB8,0x02,0x00,0x00,0x00});
    asmData = asmData + makeByteArray({0x48,0xBA,0xC0,0x4E,0x65,0x1B,0xF7,0x7F,0x00,0x00});

    // asmData = asmData + raw_bytearray;

    // 使用RIP相对的绝对间接跳转，避免远程内存与HOOK地址相距超过2GB时
    // 32位相对偏移溢出，同时不破坏刚刚恢复的任何通用寄存器。
    asmData = asmData + makeByteArray({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}) + longToBytes(hook_address + kHookCodeSize);
    // 写入汇编，HOOK启动
    if (!writeMemory(pid, asmcode_address, asmData.size(), asmData.data())) {
        qDebug() << "写入汇编失败~";
        cleanupPartial();
        return false;
    }

    // 构造JMP指令，跳转到我们的代码
    // mov rax, 0x0000000142F0147C  ;48 B8 XX
    // jmp rax                      ;FF E0
    // nop                          ;90
    // 需要15个字节
    BYTE jmp_code[kHookCodeSize] = {0};
    jmp_code[0] = 0x48;
    jmp_code[1] = 0xB8;
    jmp_code[kHookCodeSize-3] = 0xFF;
    jmp_code[kHookCodeSize-2] = 0xE0;
    jmp_code[kHookCodeSize-1] = 0x90;

    ULONG64 jmp_address = asmcode_address;
    memcpy(&jmp_code[2], &jmp_address, 8);

    qDebug() << "开始安装EPT HOOK";

    for_each_cpu([&](uint32_t cpu_id) {
        if (install_ept_hook(hook_pfn, shadow_pfn)) {
            qDebug() << "EPT安装成功，CPU：" + QString::number(cpu_id);
        }else{
            qDebug() << "EPT安装失败，CPU：" + QString::number(cpu_id);
        }
    });

    qDebug() << "EPT HOOK安装完毕";
    ept_installed = true;

    // 修改
    write_virt_mem(target_cr3, reinterpret_cast<void*>(hook_address), jmp_code, kHookCodeSize);

    // 读取修改结果，验证
    BYTE read_code[kHookCodeSize] = {0};
    read_virt_mem(target_cr3, read_code, reinterpret_cast<void*>(hook_address), kHookCodeSize);

    _hook_data.is_hooked = true;
    _hook_data.pid = pid;
    _hook_data.hook_address = hook_address;
    _hook_data.allocated_address = asmcode_address;
    _hook_data.shadowpage_address = shadowpage_address;
    _hook_data.hook_pfn = hook_pfn;
    memcpy(_hook_data.raw_bytecode, raw_bytecode, kHookCodeSize);

    return true;
}

bool MsgFilterWindow::unhook()
{
    if (_hook_data.is_hooked) {
        if (_hook_data.hook_pfn != 0) {
            remove_ept_hook(_hook_data.hook_pfn);
        }
        _hook_data.is_hooked = false;
    }

    if (_hook_data.shadowpage_address != 0) {
        if (!freeMemory(_hook_data.pid, _hook_data.shadowpage_address)) {
            return false;
        }
        _hook_data.shadowpage_address = 0;
    }

    if (_hook_data.allocated_address != 0) {
        if (!freeMemory(_hook_data.pid, _hook_data.allocated_address)) {
            return false;
        }
        _hook_data.allocated_address = 0;
    }

    _hook_data = {};
    return true;
}

bool MsgFilterWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    if (eventType == "windows_generic_MSG") {
        MSG *msg = static_cast<MSG*>(message);
        if (msg->message == WM_MY_CUSTOM_MESSAGE) {

            LPARAM lParam = msg->lParam;
            qDebug() << "接收指针：" << QString::number(lParam, 16);

            const int row = ui->tableWidget_msgList->rowCount();
            ui->tableWidget_msgList->insertRow(row);
            ui->tableWidget_msgList->setItem(
                row,
                0,
                new QTableWidgetItem(QDateTime::currentDateTime().toString(QStringLiteral("hh:mm:ss.zzz"))));
            ui->tableWidget_msgList->setItem(
                row,
                1,
                new QTableWidgetItem(
                    QStringLiteral("0x%1").arg(static_cast<qulonglong>(msg->lParam), 0, 16).toUpper()));
            ui->tableWidget_msgList->scrollToBottom();

            if (result) {
                *result = 0;
            }
            return true;
        }
    }

    return QDialog::nativeEvent(eventType, message, result);
}

void MsgFilterWindow::on_pushButton_startHook_clicked()
{
    if(_hook_data.is_hooked)
    {
        QMessageBox::information(this, tr("提示"), tr("当前窗口已经启用HOOK。"));
        return;
    }

    const QString process_text = ui->lineEdit_processId->text().trimmed();
    QString process_address = ui->lineEdit_processAddress->text().trimmed();

    if (process_text.isEmpty() || process_address.isEmpty()) {
        QMessageBox::warning(this, tr("参数错误"), tr("请输入目标进程名和HOOK地址。"));
        return;
    }

    DWORD target_pid = 0;

    const std::wstring process_name = process_text.toStdWString();
    target_pid = getPid(process_name.c_str());


    if(target_pid == 0)
    {
        QMessageBox::warning(this, tr("进程错误"), tr("找不到目标进程，请检查进程ID或进程名。"));
        return;
    }

    if (process_address.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) {
        process_address.remove(0, 2);
    }
    bool address_ok = false;
    const ULONG64 target_address = process_address.toULongLong(&address_ok, 16);

    if(!address_ok || target_address == 0){
        QMessageBox::warning(this, tr("地址错误"), tr("HOOK地址不是有效的十六进制地址。"));
        return;
    }

    ULONG meminfo = 0;
    const bool query_addres_result = queryMemory(target_pid,target_address,meminfo);
    if(!query_addres_result){
        QMessageBox::critical(this, tr("HOOK失败"), tr("无法查询目标进程中的HOOK地址。"));
        return;
    }
    if(!isExecutableProtection(meminfo))
    {
        QMessageBox::warning(this, tr("地址错误"), tr("HOOK地址所在内存不可执行，请检查目标函数地址。"));
        return;
    }

    qDebug() << "目标PID：" << target_pid;
    qDebug() << "函数地址：" << QString::number(target_address,16).toUpper();

    // 如果未开启HOOK，则创建一个HOOK
    if (!hook(target_pid,target_address)) {
        QMessageBox::critical(this, tr("HOOK失败"), tr("安装HOOK失败，已清理本次分配的远程内存。"));
        return;
    }

    ui->lineEdit_processId->setEnabled(false);
    ui->lineEdit_processAddress->setEnabled(false);
    ui->pushButton_startHook->setEnabled(false);
    QMessageBox::information(this, tr("HOOK成功"), tr("HOOK已成功安装。"));
}


void MsgFilterWindow::on_pushButton_destroyWindow_clicked()
{
    if (!unhook()) {
        QMessageBox::critical(this,
                              tr("清理失败"),
                              tr("还原HOOK或释放远程内存失败。窗口将保持打开，请确认目标进程仍在运行后重试。"));
        return;
    }

    close();
    deleteLater();
}

