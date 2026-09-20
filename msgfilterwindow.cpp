#include "msgfilterwindow.h"
#include "ui_msgfilterwindow.h"

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

void MsgFilterWindow::hook()
{
    // 寻找目标PID

    // 找出目标进程，user32模块SendMessageA函数地址

    // 在目标进程中申请一段内存

    // 如果申请的内存地址与HOOK地址相差太远，则不能进行HOOK。

    // 如果未开启HOOK，则创建一个HOOK

    // 计算CALL偏移值

    // 需要保存HOOK位置原始字节码

    // 构造JMP指令，跳转到我们的代码

     // 校验CALL计算是否合法

    // 构造PostMessageA函数汇编

    // 写入汇编，HOOK启动
}
