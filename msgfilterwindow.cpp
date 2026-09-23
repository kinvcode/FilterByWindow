#include "msgfilterwindow.h"
#include "ui_msgfilterwindow.h"
#include "drv/PeaceDriverAPI.h"

#include <QCheckBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QMessageBox>
#include <QTableWidgetItem>
#include <cstring>
#include <limits>
#include <memory>

namespace {

constexpr ULONG64 kRemoteBufferSize = 0x1000;
constexpr ULONG64 HOOK_ADDRESS      = 0x14668CDE0;
constexpr BOOL    USE_EPT_HOOK      = TRUE;

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

QString formatBytesHex(const void* data, size_t len)
{
    const auto* bytes = static_cast<const byte*>(data);
    QString out;
    for (size_t i = 0; i < len; ++i) {
        if (i != 0) {
            out += QChar(' ');
        }
        out += QStringLiteral("%1").arg(static_cast<uint>(bytes[i]), 2, 16, QChar('0')).toUpper();
    }
    return out;
}

bool bufferEqual(const void* a, const void* b, size_t len)
{
    return std::memcmp(a, b, len) == 0;
}

}

MsgFilterWindow::MsgFilterWindow(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::MsgFilterWindow)
{
    ui->setupUi(this);

    ui->tableWidget_msgList->setColumnCount(3);
    ui->tableWidget_msgList->setHorizontalHeaderLabels({tr("时间"), tr("窗口类型"), tr("窗口名称")});
    ui->tableWidget_msgList->horizontalHeader()->setStretchLastSection(true);

    ui->tableWidget_filterId->setColumnCount(3);
    ui->tableWidget_filterId->setColumnWidth(0, 50);
    ui->tableWidget_filterId->setHorizontalHeaderLabels({tr("ID过滤"), tr("ID"), tr("窗口名称")});
    ui->tableWidget_filterId->horizontalHeader()->setStretchLastSection(true);

    filter_cate = {
        {0x1D1, QStringLiteral("个人信息"), true},
        {0x1D2, QStringLiteral("物品栏"), true},
    };
    initFilterTable();
}

void MsgFilterWindow::initFilterTable()
{
    ui->tableWidget_filterId->setRowCount(static_cast<int>(filter_cate.size()));

    for (int row = 0; row < static_cast<int>(filter_cate.size()); ++row) {
        const FilterCate& entry = filter_cate[static_cast<size_t>(row)];

        auto* check_box = new QCheckBox();
        check_box->setChecked(entry.active);
        const uint32_t filter_id = entry.id;
        connect(check_box, &QCheckBox::toggled, this, [this, filter_id](bool checked) {
            setFilterActive(filter_id, checked);
        });

        auto* check_box_container = new QWidget(ui->tableWidget_filterId);
        auto* check_box_layout = new QHBoxLayout(check_box_container);
        check_box_layout->setContentsMargins(0, 0, 0, 0);
        check_box_layout->setAlignment(Qt::AlignCenter);
        check_box_layout->addWidget(check_box);
        ui->tableWidget_filterId->setCellWidget(row, 0, check_box_container);

        auto* id_item = new QTableWidgetItem(
            QStringLiteral("0x%1").arg(entry.id, 0, 16).toUpper());
        id_item->setFlags(id_item->flags() & ~Qt::ItemIsEditable);
        ui->tableWidget_filterId->setItem(row, 1, id_item);

        auto* name_item = new QTableWidgetItem(entry.name);
        name_item->setFlags(name_item->flags() & ~Qt::ItemIsEditable);
        ui->tableWidget_filterId->setItem(row, 2, name_item);
    }
}

QString MsgFilterWindow::filterNameForId(uint32_t id) const
{
    for (const FilterCate& entry : filter_cate) {
        if (entry.id == id) {
            return entry.name;
        }
    }
    return tr("未知");
}

bool MsgFilterWindow::isFilterActive(uint32_t id) const
{
    for (const FilterCate& entry : filter_cate) {
        if (entry.id == id) {
            return entry.active;
        }
    }
    return false;
}

void MsgFilterWindow::setFilterActive(uint32_t id, bool active)
{
    for (FilterCate& entry : filter_cate) {
        if (entry.id == id) {
            qDebug() << "窗口ID:0x" + QString::number(id,16).toUpper() << (active ? "激活" : "取消过滤");
            entry.active = active;
            return;
        }
    }
}

MsgFilterWindow::~MsgFilterWindow()
{
    if (!unhook()) {
        qWarning() << "窗口销毁时清理HOOK失败";
    }
    delete ui;
}


bool MsgFilterWindow::hook(DWORD pid)
{
    ULONG64   shadowpage_address  = 0;
    ULONG64   asmcode_address     = 0;
    uint64_t  hook_pfn            = 0;
    uint64_t  shadow_pfn          = 0;
    bool      ept_installed       = false;
    ULONG64   target_cr3          = 0;

    const auto cleanupPartial = [&]() {
        if(USE_EPT_HOOK){
            if (ept_installed && hook_pfn != 0) {
                for_each_cpu([hook_pfn](uint32_t cpu_id) {
                    Q_UNUSED(cpu_id);
                    remove_ept_hook(hook_pfn);
                });
                ept_installed = false;
            }
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

    ULONG64 hook_address = HOOK_ADDRESS; // 依靠特征码
    // 计算HOOK页面的地址和hook位置偏移
    uintptr_t hook_page_start  = hook_address & ~0xFFF;
    void*     hook_page_ptr    = reinterpret_cast<void*>(hook_page_start);
    uintptr_t hook_offset      = hook_address - reinterpret_cast<uintptr_t>(hook_page_ptr);
    qDebug() << "HOOK页面起始地址：" << QString::number((uint64_t)hook_page_ptr,16).toUpper();
    qDebug() << "HOOK函数偏移："    << QString::number((uint64_t)hook_offset,16).toUpper();

    if(USE_EPT_HOOK){
        // 读取目标程序CR3
        target_cr3 = query_process_cr3(pid);
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
        shadow_pfn = shadow_phys_addr >> 12;
        qDebug() << "影子页物理页帧号(PFN)：" << QString::number(shadow_pfn,16).toUpper();
    }


    // 创建汇编函数执行页
    // 在目标进程中申请一段内存
    asmcode_address = allocMemory(pid, kRemoteBufferSize);
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

    asmData = asmData + makeByteArray({0x9C});                      // pushfq
    asmData = asmData + makeByteArray({0x50});                      // push rax
    asmData = asmData + makeByteArray({0x53});                      // push rbx
    asmData = asmData + makeByteArray({0x51});                      // push rcx
    asmData = asmData + makeByteArray({0x52});                      // push rdx
    asmData = asmData + makeByteArray({0x56});                      // push rsi
    asmData = asmData + makeByteArray({0x57});                      // push rdi
    asmData = asmData + makeByteArray({0x55});                      // push rbp
    asmData = asmData + makeByteArray({0x41, 0x50});                // push r8
    asmData = asmData + makeByteArray({0x41, 0x51});                // push r9
    asmData = asmData + makeByteArray({0x41, 0x52});                // push r10
    asmData = asmData + makeByteArray({0x41, 0x53});                // push r11
    asmData = asmData + makeByteArray({0x41, 0x54});                // push r12
    asmData = asmData + makeByteArray({0x41, 0x55});                // push r13
    asmData = asmData + makeByteArray({0x41, 0x56});                // push r14
    asmData = asmData + makeByteArray({0x41, 0x57});                // push r15
    asmData = asmData + makeByteArray({0x48, 0x83, 0xEC, 0x28});    // sub rsp, 0x28 → RSP ≡ 0 (mod 16)

    // hook后的实际逻辑
    asmData = asmData + makeByteArray({0x4C, 0x8B, 0xCA});                                  // mov r9, rdx // 数据指针传给参数4
    asmData = asmData + makeByteArray({0x4D, 0x31, 0xC0});                                  // xor r8, r8
    asmData = asmData + makeByteArray({0x48, 0xBA}) + longToBytes(WM_MY_CUSTOM_MESSAGE);    // mov rdx,消息类型
    asmData = asmData + makeByteArray({0x48, 0xB9}) + longToBytes(my_window_handle);        // mov rcx,窗口句柄
    asmData = asmData + makeByteArray({0x48, 0xB8}) + longToBytes(PostMessageA);            // mov rax, PostMessageA
    asmData = asmData + makeByteArray({0xFF, 0xD0});                                        // call rax

    asmData = asmData + makeByteArray({0x48, 0x83, 0xC4, 0x28});    // add rsp, 0x28
    asmData = asmData + makeByteArray({0x41, 0x5F});                // pop r15
    asmData = asmData + makeByteArray({0x41, 0x5E});                // pop r14
    asmData = asmData + makeByteArray({0x41, 0x5D});                // pop r13
    asmData = asmData + makeByteArray({0x41, 0x5C});                // pop r12
    asmData = asmData + makeByteArray({0x41, 0x5B});                // pop r11
    asmData = asmData + makeByteArray({0x41, 0x5A});                // pop r10
    asmData = asmData + makeByteArray({0x41, 0x59});                // pop r9
    asmData = asmData + makeByteArray({0x41, 0x58});                // pop r8
    asmData = asmData + makeByteArray({0x5D});                      // pop rbp
    asmData = asmData + makeByteArray({0x5F});                      // pop rdi
    asmData = asmData + makeByteArray({0x5E});                      // pop rsi
    asmData = asmData + makeByteArray({0x5A});                      // pop rdx
    asmData = asmData + makeByteArray({0x59});                      // pop rcx
    asmData = asmData + makeByteArray({0x5B});                      // pop rbx
    asmData = asmData + makeByteArray({0x58});                      // pop rax
    asmData = asmData + makeByteArray({0x9D});                      // popfq

    // 执行被覆盖指令，然后跳回hook继续执行
    asmData = asmData + makeByteArray({0x48, 0x8B, 0xC4});          // mov rax, rsp
    asmData = asmData + makeByteArray({0x4C, 0x89, 0x48, 0x20});    // mov [rax+0x20], r9
    asmData = asmData + makeByteArray({0x4C, 0x89, 0x40, 0x18});    // mov [rax+0x18], r8
    asmData = asmData + makeByteArray({0x89, 0x50, 0x10});          // mov [rax+0x10], edx
    asmData = asmData + makeByteArray({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});	// jmp [rip+0]
    asmData = asmData + longToBytes(hook_address + kHookCodeSize);              // hook位置,kHookCodeSize是覆盖指令的大小


    // 写入汇编，HOOK启动
    if (!writeMemory(pid, asmcode_address, asmData.size(), asmData.data())) {
        qDebug() << "写入汇编失败~";
        cleanupPartial();
        return false;
    }

    // 构造JMP指令，跳转到我们的代码
    // 使用 mov rax, imm64; jmp rax，避免 FF 25 在同页再读 8 字节：
    // EPT 下执行常走影子页、读常走原页，RIP 相对寻址会读到未 patch 的原页数据。
    BYTE jmp_code[kHookCodeSize] = {0};
    jmp_code[0] = 0x48;
    jmp_code[1] = 0xB8;
    const ULONG64 jmp_address = asmcode_address;
    memcpy(&jmp_code[2], &jmp_address, 8);
    jmp_code[10] = 0xFF;
    jmp_code[11] = 0xE0;
    jmp_code[12] = 0x90;
    jmp_code[13] = 0x90;

    if(USE_EPT_HOOK){
        // 影子页HOOK位置
        const ULONG64 shadow_patch_va = shadowpage_address + hook_offset;

        // 影子页开启HOOK
        if (!writeMemory(pid, shadow_patch_va, kHookCodeSize, jmp_code)) {
            qDebug() << "写入影子页HOOK指令失败";
            cleanupPartial();
            return false;
        }

        // 影子页物理地址
        uint64_t shadow_phys_addr_after = get_physical_address(target_cr3, reinterpret_cast<void*>(shadowpage_address));
        if (!shadow_phys_addr_after) {
            qDebug() << "patch 后无法解析影子页物理地址";
            cleanupPartial();
            return false;
        }
        // 影子页物理帧
        shadow_pfn = shadow_phys_addr_after >> 12;

        qDebug() << "开始安装EPT HOOK";

        // 查询CPU信息
        SYSTEM_INFO cpu_info = {};
        GetSystemInfo(&cpu_info);
        const uint32_t cpu_count = cpu_info.dwNumberOfProcessors;
        uint32_t success_count = 0;

        // 在每一个CPU上面安装EPT HOOK
        for_each_cpu([&](uint32_t cpu_id) {
            // 交换hook页和影子页实现【读、执行】分离策略
            if (install_ept_hook(hook_pfn, shadow_pfn)) {
                qDebug() << "EPT安装成功，CPU：" + QString::number(cpu_id);
                ++success_count;
            } else {
                qDebug() << "EPT安装失败，CPU：" + QString::number(cpu_id);
            }
        });

        // 如果安装EPT失败，则回滚
        if (success_count != cpu_count) {
            for_each_cpu([hook_pfn](uint32_t cpu_id) {
                Q_UNUSED(cpu_id);
                remove_ept_hook(hook_pfn);
            });
            cleanupPartial();
            return false;
        }

        qDebug() << "EPT HOOK安装完毕";
        ept_installed = true;

    }else{
        if (!writeMemory(pid, hook_address, kHookCodeSize, jmp_code)) {
            qDebug() << "写入HOOK跳转失败";
            cleanupPartial();
            return false;
        }
        BYTE hook_after[kHookCodeSize] = {};
        if (readMemory(pid, hook_address, kHookCodeSize, hook_after)) {
            qDebug() << "[非EPT] hook 回读:" << formatBytesHex(hook_after, kHookCodeSize)
                     << "与jmp一致=" << bufferEqual(hook_after, jmp_code, kHookCodeSize);
        }
    }

    _hook_data.is_hooked = true;
    _hook_data.pid = pid;
    _hook_data.hook_address = hook_address;
    _hook_data.allocated_address = asmcode_address;
    _hook_data.shadowpage_address = shadowpage_address;
    _hook_data.hook_pfn = hook_pfn;
    if (USE_EPT_HOOK) {
        _hook_data.target_cr3 = target_cr3;
        _hook_data.hook_execute_patched = true;
    }
    memcpy(_hook_data.raw_bytecode, raw_bytecode, kHookCodeSize);

    return true;
}

bool MsgFilterWindow::unhook()
{
    if(USE_EPT_HOOK){
        if (_hook_data.hook_execute_patched && _hook_data.target_cr3 != 0
            && _hook_data.hook_address != 0) {
            const size_t restored = write_virt_mem(
                _hook_data.target_cr3,
                reinterpret_cast<void*>(_hook_data.hook_address),
                _hook_data.raw_bytecode,
                kHookCodeSize);
            qDebug() << "[EPT] 还原执行页 raw_bytecode bytes=" << restored;
        }

        if (_hook_data.is_hooked) {
            if (_hook_data.hook_pfn != 0) {
                qDebug() << "EPT HOOK卸载";
                const uint64_t hook_pfn = _hook_data.hook_pfn;
                for_each_cpu([hook_pfn](uint32_t cpu_id) {
                    Q_UNUSED(cpu_id);
                    remove_ept_hook(hook_pfn);
                });
            }
            _hook_data.is_hooked = false;
        }

        if (_hook_data.shadowpage_address != 0) {
            qDebug() << "释放影子页";
            if (!freeMemory(_hook_data.pid, _hook_data.shadowpage_address)) {
                return false;
            }
            _hook_data.shadowpage_address = 0;
        }
    }

    if (_hook_data.allocated_address != 0) {
        qDebug() << "释放汇编页";
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

            const uint32_t filter_id = static_cast<uint32_t>(msg->lParam);
            qDebug() << "[MSG] 收到 WM_MY_CUSTOM_MESSAGE lParam=0x"
                     << QString::number(filter_id, 16).toUpper();

            if (isFilterActive(filter_id)) {
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
                        QStringLiteral("0x%1").arg(static_cast<qulonglong>(filter_id), 0, 16).toUpper()));
                ui->tableWidget_msgList->setItem(
                    row,
                    2,
                    new QTableWidgetItem(filterNameForId(filter_id)));
                ui->tableWidget_msgList->scrollToBottom();
            }

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
    if(!is_hv_running()){
        QMessageBox::warning(this, tr("提示"), tr("未安装驱动！"));
        return;
    }

    if(_hook_data.is_hooked)
    {
        QMessageBox::information(this, tr("提示"), tr("当前窗口已经启用HOOK。"));
        return;
    }

    const QString process_text = ui->lineEdit_processId->text().trimmed();

    if (process_text.isEmpty()) {
        QMessageBox::warning(this, tr("参数错误"), tr("请输入目标进程名"));
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

    const ULONG64 target_address = HOOK_ADDRESS;

    if(target_address == 0){
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

    // 如果未开启HOOK，则创建一个HOOK
    if (!hook(target_pid)) {
        QMessageBox::critical(this, tr("HOOK失败"), tr("安装HOOK失败，已清理本次分配的远程内存。"));
        return;
    }

    ui->lineEdit_processId->setEnabled(false);
    ui->pushButton_startHook->setEnabled(false);
    QMessageBox::information(this, tr("HOOK成功"), tr("HOOK已成功安装。"));
}


void MsgFilterWindow::closeEvent(QCloseEvent* event)
{
    const auto answer = QMessageBox::question(
        this,
        tr("确认关闭"),
        tr("是否确认关闭？关闭后过滤数据不可恢复"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (answer != QMessageBox::Yes) {
        event->ignore();
        return;
    }

    if (!unhook()) {
        QMessageBox::critical(this,
                              tr("清理失败"),
                              tr("还原HOOK或释放远程内存失败。窗口将保持打开，请确认目标进程仍在运行后重试。"));
        event->ignore();
        return;
    }

    event->accept();
    deleteLater();
}

void MsgFilterWindow::on_pushButton_destroyWindow_clicked()
{
    close();
}

