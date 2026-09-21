#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "msgfilterwindow.h"
#include <QMessageBox>
#include <QTabBar>
#include <QStandardItemModel>
#include <QStandardItem>

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <hidclass.h>
#include <hidsdi.h>
#include <cstdlib>

#include "drv/PeaceDriverAPI.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_addHook_clicked()
{
    qDebug() << "123456";

    MsgFilterWindow* msg_win = new MsgFilterWindow();
    msg_win->show();

    _window_vector.push_back(msg_win);
}

bool MainWindow::nativeEvent(const QByteArray &eventType, void *message, qintptr *result)
{
    if (eventType == "windows_generic_MSG") {
        MSG *msg = static_cast<MSG*>(message);
        if (msg->message == WM_MY_CUSTOM_MESSAGE) {
            // qDebug() << "收到自定义消息";

            // WPARAM wParam = msg->wParam;
            // qDebug() << "整数指针：" << QString::number(wParam);
            LPARAM lParam = msg->lParam;
            qDebug() << "收包数据指针：" << QString::number(lParam, 16);

            *result = 0;
            return true;  // 表示消息已处理
        }
    }

    return QMainWindow::nativeEvent(eventType, message, result);
}
