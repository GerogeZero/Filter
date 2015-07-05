ifneq ($(KERNELRELEASE),)  
obj-m:=filter.o  
else  
KERNELDIR ?=/lib/modules/$(shell uname -r)/build  
PWD:=$(shell pwd)  
all:  
	make -C $(KERNELDIR) M=$(PWD) modules   
clean:  
	rm -rf *.ko *.o *.mod.c *.mod.o *.symvers *~ 
endif  

