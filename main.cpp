#include "mainwindow.h"

#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QIcon>
#include <QMessageBox>

#include "drv/PeaceDriverAPI.h"
#include "drv/PeaceDriverLoad.h"

namespace {

bool applyGlobalStyleSheet(QApplication& app)
{
    QFile style_file(QStringLiteral(":/assets/app.qss"));
    if (!style_file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return false;
    }
    app.setStyleSheet(QString::fromUtf8(style_file.readAll()));
    return true;
}

bool loadPeaceDRV()
{
    PeaceDriverLoad drv;
    if (!drv.driverIsLoaded()) {
        // 加载驱动
        PeaceDriverLoad::LoadDriverResult load_result = drv.loadPeaceDriver();
        if (!load_result.success) {
            qDebug() << "VT驱动安装失败";
            qDebug() << (QString::fromWCharArray(load_result.message));
            QMessageBox::information(nullptr, "提示", QString::fromWCharArray(load_result.message));
            return false;
        }
    }

    return drv.driverIsLoaded() != FALSE;
}

bool loadDriver()
{
    // 检测驱动是否已开启
    if (!is_hv_running()) {
        // 初始化驱动
        if (!loadPeaceDRV()) {
            return false;
        }
    }

    qDebug() << "驱动初始化完毕！";
    return true;
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setWindowIcon(QIcon(QStringLiteral(":/assets/logo.ico")));
    applyGlobalStyleSheet(a);

    if (!loadDriver()) {
        // 驱动不可用，直接退出
        return 0;
    }

    MainWindow w;
    w.show();
    return QApplication::exec();
}
