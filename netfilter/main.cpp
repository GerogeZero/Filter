#include "netfilter.h"
#include <QApplication>
#include "login.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    netfilter w;
    login Login;
    if(Login.exec() == QDialog::Accepted)
    {
        w.show();
        return app.exec();
    }

    else
        return 0;

}
