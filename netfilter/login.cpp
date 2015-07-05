#include "login.h"
#include "ui_login.h"
#include <QMessageBox>

login::login(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::login)
{
    ui->setupUi(this);
    ui->pwdLineEdit->setEchoMode(QLineEdit::Password);
}

login::~login()
{
    delete ui;
}

void login::on_loginBtn_clicked()
{
    if(ui->usrLineEdit->text().trimmed() == tr("1") && ui->pwdLineEdit->text() == tr("1"))
        accept();
    else{
        QMessageBox::warning(this, tr("Warning"), tr("user name or password error!"),QMessageBox::Yes);
        ui->pwdLineEdit->clear();
        ui->usrLineEdit->setFocus();
    }
}
