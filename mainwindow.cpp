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
    if (_msg_filter_window) {
        qDebug() << "窗口已存在，直接显示";
        _msg_filter_window->show();
        _msg_filter_window->raise();
        _msg_filter_window->activateWindow();
        return;
    }

    qDebug() << "创建新窗口";
    _msg_filter_window = new MsgFilterWindow();
    _msg_filter_window->show();
}


