#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "msgfilterwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

#define WM_MY_CUSTOM_MESSAGE (WM_USER + 100)

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:

    void on_pushButton_addHook_clicked();
private:
    bool nativeEvent(const QByteArray &eventType, void *message, qintptr *result);
private:
    Ui::MainWindow *ui;
    std::vector<MsgFilterWindow*> _window_vector;
};
#endif // MAINWINDOW_H
