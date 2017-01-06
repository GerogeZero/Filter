#include "netfilter.h"
#include <QApplication>
#include "login.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    netfilter filter;
    login userLogin;

    if(userLogin.exec() == QDialog::Accepted)
    {
        filter.add_device();
        filter.show();
        return app.exec();
    }

    else
        return 0;

}
