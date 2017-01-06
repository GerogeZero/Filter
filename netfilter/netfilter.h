#ifndef NETFILTER_H
#define NETFILTER_H

#include <QWidget>

namespace Ui {
class netfilter;
}

class netfilter : public QWidget
{
    Q_OBJECT
    
public:
    explicit netfilter(QWidget *parent = 0);
    ~netfilter();
    void add_device();
    void add_deny(unsigned int, int);
    void del_deny(unsigned int, int);

private slots:
    void on_Add_IP_Btn_clicked();
    void on_Del_IP_Btn_clicked();
    void on_Add_PORT_Btn_clicked();
    void on_Del_PORT_Btn_clicked();

private:
    Ui::netfilter *ui;
    int fd;
};

#endif // NETFILTER_H
