#include "netfilter.h"
#include "ui_netfilter.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

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

    fd = open("/dev/filter", O_RDWR);
    if(fd <= 0)
    {
        ui->textEdit->setText("open /dev/filter error");
    }
    else
    {
        ui->textEdit->setText("open /dev/filter success");
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

netfilter::~netfilter()
{
    delete ui;
}

void netfilter::add_deny(unsigned int data, int flag)
{
    int ret = -1;
    if(flag == 0)
    {
        ret = ioctl(fd, 0, &data);
        if(ret != 0)
        {
            ui->textEdit->setText("ioctl error ADD_IP");
        }
    }
    else if(flag == 1)
    {
        ret = ioctl(fd, 3, &data);
        if(ret != 0)
        {
            ui->textEdit->setText("ioctl error ADD_IP");
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
            ui->textEdit->setText("ioctl error DEL_IP");
        }
    }
    else if(flag == 1)
    {
        ret = ioctl(fd, 4, &data);
        if(ret != 0)
        {
            ui->textEdit->setText("ioctl error DEL_PORT");
        }
    }
}

void netfilter::on_Add_IP_Btn_clicked()
{
    int i = 0;
    QString str_ip = ui->IPLineEdit->text();
    QByteArray dev = str_ip.toLatin1();
    char *sip = dev.data();
    //struct hostent *hptr;
    //hptr = gethostname(sip);

    unsigned int ip = inet_addr(sip);

    if(ip <= 0 || ip > 0xf7ffffff)
    {
        ui->textEdit->setText("ip error");
        return ;
    }

    for(i=0; i<MAX_NR; i++)
    {
        if(array_ip[i] == 0)
        {
            array_ip[i] = ip;
            add_deny(ip, 0);
            ui->textEdit->setText("add_ip success");
            return;
        }
        else if(array_ip[i] == ip)
        {
            ui->textEdit->setText("The ip exists");
            return;
        }
    }
    if(i >= MAX_NR)
    {
        ui->textEdit->setText("ip full");
        return;
    }
}

void netfilter::on_Del_IP_Btn_clicked()
{
    int i = 0;
    QString str_ip = ui->IPLineEdit->text();
    QByteArray dev = str_ip.toLatin1();
    char *sip = dev.data();
    unsigned int ip = inet_addr(sip);

    if(ip <= 0 || ip > 0xf7ffffff)
    {
        ui->textEdit->setText("The ip error");
        return ;
    }

    for(i=0; i<MAX_NR; i++)
    {
        if(array_ip[i] == ip)
        {
            array_ip[i] = 0;
            del_deny(ip, 0);
            ui->textEdit->setText("del_ip success");
            return ;
        }
    }
    if(i >= MAX_NR)
    {
        ui->textEdit->setText("The ip don't exist");
        return;
    }
}

void netfilter::on_Add_PORT_Btn_clicked()
{
    int i = 0;
    QString str_port = ui->PORTLineEdit->text();
    unsigned short port = str_port.toInt();

    if(port < 1 || port > 65535)
    {
        ui->textEdit->setText("The port error");
        return ;
    }

    for(i=0; i<MAX_NR; i++)
    {

        if(array_port[i] == 0)
        {
            array_port[i] = port;
            add_deny(port, 1);
            ui->textEdit->setText("add_port success");
            return ;
        }
        else if(array_port[i] == port)
        {
            ui->textEdit->setText("The port exist");
            return ;
        }
    }

    if(i >= MAX_NR)
    {
        ui->textEdit->setText("port FULL");
        return;
    }
}

void netfilter::on_Del_PORT_Btn_clicked()
{
    int i=0;
    QString str_port = ui->PORTLineEdit->text();
    unsigned short port = str_port.toInt();

    if(port < 1 || port > 65535)
    {
        ui->textEdit->setText("The port error");
        return ;
    }
    for(i=0; i<MAX_NR; i++)
    {
        if(array_port[i] == port)
        {
            array_port[i] = 0;
            del_deny(port, 1);
            ui->textEdit->setText("del port success");
            return ;
        }
    }

    if(i >= MAX_NR)
    {
        ui->textEdit->setText("The port don't exist");
        return ;
    }
}

void netfilter::on_Display_IP_Btn_clicked()
{
    int i = 0;
    char *ch_ip;
    QString text("");
    struct in_addr ip;
    for(i=0; i<MAX_NR; i++)
    {
        if(array_ip[i] != 0)
        {
            ip.s_addr = array_ip[i];
            ch_ip = inet_ntoa(ip);
            text.append(ch_ip);
            text.append("<br />");
        }
    }
    ui->textview->setHtml(text);
    ui->textEdit->setText("Display ip!");
}

void netfilter::on_Disay_PORT_Btn_clicked()
{
    QString text("");
    int i = 0;
    for(i=0; i<MAX_NR; i++)
    {
        if(array_port[i] != 0)
        {
            text += QString::number(array_port[i], 10);
            text.append("<br />");
        }
    }
    ui->textview->setHtml(text);
    ui->textEdit->setText("Display port");
}
