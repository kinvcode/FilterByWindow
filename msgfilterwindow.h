#ifndef MSGFILTERWINDOW_H
#define MSGFILTERWINDOW_H

#include <QDialog>

namespace Ui {
class MsgFilterWindow;
}

class MsgFilterWindow : public QDialog
{
    Q_OBJECT

public:
    explicit MsgFilterWindow(QWidget *parent = nullptr);
    ~MsgFilterWindow();

private:
    Ui::MsgFilterWindow *ui;

    void hook();
};

#endif // MSGFILTERWINDOW_H
