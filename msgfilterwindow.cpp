#include "msgfilterwindow.h"
#include "ui_msgfilterwindow.h"
#include "drv/PeaceDriverAPI.h"

MsgFilterWindow::MsgFilterWindow(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::MsgFilterWindow)
{
    ui->setupUi(this);
}

MsgFilterWindow::~MsgFilterWindow()
{
    delete ui;
}


bool MsgFilterWindow::hook(DWORD pid, ULONG64 hook_address)
{
    // 找出目标进程，user32模块PostMessageA函数地址
    const ULONG64 moduleBase = getModuleBase(pid, L"user32.dll");
    if(moduleBase == 0){
        return false;
    }

    const ULONG64 PostMessageA = getModuleExport(pid, moduleBase, "PostMessageA");
    if(PostMessageA == 0){
        return false;
    }

    // 在目标进程中申请一段内存
    ULONG64 newmem_address = allocMemory(pid, 0x1000);
    if(newmem_address == 0){
        return false;
    }

    // mov rax, 0x0000000142F0147C  ;48 B8 XX
    // jmp rax                      ;FF E0
    // 需要12个字节
    const int hook_length = 12;

    // 需要保存HOOK位置原始字节码
    BYTE raw_bytecode[hook_length] = {0};
    bool read_res = readMemory(pid, hook_address, hook_length, &raw_bytecode);
    if(!read_res){
        return false;
    }
    memcpy(_hook_data.raw_bytecode,raw_bytecode,hook_length);

    // 构造JMP指令，跳转到我们的代码
    BYTE jmp_code[hook_length] = {0};
    jmp_code[0] = 0x48;
    jmp_code[1] = 0xB8;
    jmp_code[hook_length-2] = 0xFF;
    jmp_code[hook_length-1] = 0xE0;
    memcpy(&jmp_code[2], &newmem_address, 8);

    // 获取本窗口句柄
    HWND hwnd = reinterpret_cast<HWND>(this->winId());
    UINT_PTR my_window_handle = reinterpret_cast<UINT_PTR>(hwnd);

    // 构造PostMessageA函数汇编
    int returnOffset;

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
    // asmData = asmData + makeByteArray({0x49, 0x8B, 0xF0});                  // mov rsi, r8
    asmData = asmData + makeByteArray({0x41, 0x0F, 0xB7, 0x78, 0x01});      // movzx edi, word ptr [r8+01]
    // asmData = asmData + makeByteArray({0xBB, 0xC7, 0x00, 0x00, 0x00});      // mov ebx, 0x000000C7
    // asmData = asmData + makeByteArray({0x66, 0x3B, 0xFB});                  // cmp di, bx
    // asmData = asmData + makeByteArray({0xFF, 0x25, 0x00, 0x00, 0x00, 0x00}) + longToBytes(return_address);
    returnOffset = (hook_address + hook_length) - (newmem_address + asmData.size() + 5);
    asmData = asmData + makeByteArray({0xE9}) + intToBytes(returnOffset);    // jmp HOOK返回位置



    // 写入汇编，HOOK启动
    writeMemory(pid, newmem_address, asmData.data(), asmData.size());
    writeMemory(pid, hook_address, jmp_code, hook_length);

    return true;
}

void MsgFilterWindow::unhook()
{
    // 还原hook位置代码
    if(_hook_data.is_hooked){
        writeMemory(_hook_data.pid, _hook_data.hook_address, _hook_data.raw_bytecode, 12);
        freeMemory(_hook_data.pid, _hook_data.hook_address);
    }

    // 销毁本窗口
}

void MsgFilterWindow::on_pushButton_startHook_clicked()
{
    if(_hook_data.is_hooked)
    {
        qDebug() << "已经HOOK了";
        return;
    }

    QString process_name = ui->lineEdit_processId->text();
    QString process_address = ui->lineEdit_processAddress->text();
    DWORD target_pid = getPid(process_name.toStdWString());

    if(target_pid == 0)
    {
        qDebug() << "找不到目标进程";
        return;
    }

    ULONG64 target_address = process_address.toULongLong(nullptr,16);

    if(!target_address){
        qDebug() << "非法地址";
        return;
    }

    ULONG meminfo;
    bool query_addres_result = queryMemory(target_pid,target_address,meminfo);
    if(!query_addres_result){
        qDebug() << "查询目标进程HOOK地址失败";
        return;
    }
    if((meminfo & 0xFF) != PAGE_EXECUTE)
    {
        qDebug() << "HOOK地址内存不可执行，请检查目标函数地址是否正确";
        return;
    }

    qDebug() << "目标PID：" << target_pid;
    qDebug() << "函数地址：" << target_address;

    // 如果未开启HOOK，则创建一个HOOK

    if(hook(target_pid,target_address)){
        _hook_data.is_hooked = true;
        _hook_data.pid = target_pid;
        _hook_data.hook_address = target_address;
        ui->pushButton_startHook->setDisabled(true);
    }
}


void MsgFilterWindow::on_pushButton_destroyWindow_clicked()
{
    unhook();
}

