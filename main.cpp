#include "mainwindow.h"

#include <QApplication>
#include <QFile>
#include <QIcon>

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

} // namespace

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setWindowIcon(QIcon(QStringLiteral(":/assets/logo.ico")));
    applyGlobalStyleSheet(a);

    MainWindow w;
    w.show();
    return QApplication::exec();
}
