#ifndef LOGIN_H
#define LOGIN_H

#include <QDialog>
#include <ui_login.h>

namespace  Ui {
class login;
}

class login : public QDialog
{
    Q_OBJECT

public:
    //
    explicit login(QWidget *parent = 0);
    ~login();

public slots:

private slots:
    void on_loginBtn_clicked();

private:
    Ui::login *ui;

};

#endif // LOGIN_H
