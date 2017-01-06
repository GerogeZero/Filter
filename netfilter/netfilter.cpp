#include "netfilter.h"
#include "ui_netfilter.h"
#include <QMessageBox>

#include <stdio.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

#define MAX_NR 100
#define DEVICE_NAME "/dev/filter"

#define MIN_PORT 0
#define MAX_POER 0xFFFF

/*.....................ioctl_cmd....................*/
#define ADD_IP 0
#define DEL_IP 1
#define ADD_PORT 3
#define DEL_PORT 4

/*...........................全局变量声明.............*/

FILE* fp_ip = 0;
FILE* fp_port = 0;

static unsigned int array_ip[MAX_NR];
static unsigned short array_port[MAX_NR];

netfilter::netfilter(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::netfilter)
{
    ui->setupUi(this);
}

netfilter::~netfilter()
{
    delete ui;
}

void netfilter::add_device()
{
    fd = open("/dev/filter", O_RDWR, 0777);
    cout << fd << endl;
    if(fd <= 0)
    {
        ui->messageLabel->setText("Open device file /dev/filter failed!");
    }
    else
    {
        ui->messageLabel->setText("Open device file /dev/filter succeed!");
    }

    fp_ip = fopen("ip.dat", "a+");
    if(fp_ip == NULL)
    {
        printf("fopen ip error\n");
    }
    unsigned int ip = 0;
    int i = 0;
    while(1)
    {
        int ret = 0;
        ret = fread(&ip, sizeof(unsigned int), 1, fp_ip);
        if(ret <= 0)
            break;
        array_ip[i] = ip;
        i++;
    }

    fp_port = fopen("port.dat", "a+");
    if(fp_port == NULL)
    {
        printf("fopen port error\n");
    }
    unsigned short port = 0;
    int j = 0;
    while(1)
    {
        int ret = 0;
        ret = fread(&port, sizeof(unsigned short), 1, fp_port);
        if(ret <= 0)
            break;
        array_port[j] = port;
        j++;
    }
    fclose(fp_ip);
    fclose(fp_port);
}

void netfilter::add_deny(unsigned int data, int flag)
{
    int ret = -1;
    if(flag == 0)
    {
        ret = ioctl(fd, 0, &data);
        if(ret != 0)
        {
            ui->messageLabel->setText("Function ioctl error on ADD_IP!");
        }
    }
    else if(flag == 1)
    {
        ret = ioctl(fd, 3, &data);
        if(ret != 0)
        {
            ui->messageLabel->setText("Function ioctl error on ADD_IP!");
        }
    }
}

void netfilter::del_deny(unsigned int data, int flag)
{
    int ret = -1;
    if(flag == 0)
    {
        ret = ioctl(fd, 1, &data);
        if(ret != 0)
        {
            ui->messageLabel->setText("Function ioctl error on DEL_IP!");
        }
    }
    else if(flag == 1)
    {
        ret = ioctl(fd, 4, &data);
        if(ret != 0)
        {
            ui->messageLabel->setText("Function ioctl error on DEL_PORT!");
        }
    }
}

void netfilter::on_Add_IP_Btn_clicked()
{
    int i = 0;
    QString str_ip = ui->IPLineEdit->text();
    QByteArray dev = str_ip.toLatin1();
    char *sip = dev.data();

    unsigned int ip = inet_addr(sip);

    if(ip <= 0 || ip > 0xf7ffffff)
    {
        ui->messageLabel->setText("Invalid IP address!");
    }

    for(i=0; i<MAX_NR; i++)
    {
        if(array_ip[i] == 0)
        {
            array_ip[i] = ip;
            add_deny(ip, 0);
            ui->messageLabel->setText("Add IP into blocked list succeed!");

            QListWidgetItem* ipItem = new QListWidgetItem(str_ip, ui->ipListWidget);
            ui->ipListWidget->insertItem(i+1, ipItem);

            ui->IPLineEdit->setText("");

            break;
        }
        else if(array_ip[i] == ip)
        {
            ui->messageLabel->setText("The IP has existed in blocked list!");
            break;
        }
    }

    if(i >= MAX_NR)
    {
        ui->messageLabel->setText("No more room to add this IP into list");
        return;
    }
}

void netfilter::on_Del_IP_Btn_clicked()
{
    QList<QListWidgetItem*> list = ui->ipListWidget->selectedItems();

    int i = 0;
    QString str_ip = "";
    QByteArray dev;
    char *sip = NULL;
    unsigned int ip = 0;

    if(list.size() == 0)
        return;

    QListWidgetItem* sel = list[0];
    if (sel)
    {
        str_ip = list[0]->text();
        dev = str_ip.toLatin1();
        sip = dev.data();
        ip = inet_addr(sip);

        int r = ui->ipListWidget->row(sel);
        ui->ipListWidget->takeItem(r);
    }

    if(ip <= 0 || ip > 0xf7ffffff)
    {
        ui->messageLabel->setText("Invalid IP address!");
    }

    for(i=0; i<MAX_NR; i++)
    {
        if(array_ip[i] == ip)
        {
            array_ip[i] = 0;
            del_deny(ip, 0);
            ui->messageLabel->setText("Remove IP succeed!");
            break;
        }
    }
    if(i >= MAX_NR)
    {
        ui->messageLabel->setText("The IP is not in the list!");
    }


}

void netfilter::on_Add_PORT_Btn_clicked()
{
    int i = 0;
    QString str_port = ui->PORTLineEdit->text();
    int port = str_port.toInt();

    if(port < 1 || port > 65535)
    {
        ui->messageLabel->setText("Invalid port!");
    }

    for(i=0; i<MAX_NR; i++)
    {

        if(array_port[i] == 0)
        {
            array_port[i] = port;
            add_deny(port, 1);
            ui->messageLabel->setText("Add port succeed!");

            QListWidgetItem* portItem = new QListWidgetItem(str_port, ui->portListWidget);
            ui->portListWidget->insertItem(i+1, portItem);

            ui->PORTLineEdit->setText("");

            break;
        }
        else if(array_port[i] == port)
        {
            ui->messageLabel->setText("The port has been disabled!");
            break;
        }
    }

    if(i >= MAX_NR)
    {
        ui->messageLabel->setText("No more room to add this port into list!");
    }
}

void netfilter::on_Del_PORT_Btn_clicked()
{
    QList<QListWidgetItem*> list = ui->portListWidget->selectedItems();

    int i=0;
    QString str_port = "";
    int port = 0;

    if(list.size() == 0)
        return;

    QListWidgetItem* sel = list[0];
    if (sel)
    {
        str_port = list[0]->text();
        port = str_port.toInt();

        int r = ui->portListWidget->row(sel);
        ui->portListWidget->takeItem(r);
    }

    if(port < 1 || port > 65535)
    {
        ui->messageLabel->setText("Invalid port!");
    }
    for(i=0; i<MAX_NR; i++)
    {
        if(array_port[i] == port)
        {
            array_port[i] = 0;
            del_deny(port, 1);
            ui->messageLabel->setText("Remove port from blocked list succeed!");
            break ;
        }
    }

    if(i >= MAX_NR)
    {
        ui->messageLabel->setText("The port is not in the list!");
    }
}
