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


