obj-m += kernel-module.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o loader.so loader.c -fPIC -shared -ldl -lcrypto -lcurl -Wall
	gcc -o payloadfuser payloadfuser.c -lcrypto -Wall
	strip --strip-unneeded kernel-module.ko
	strip --strip-unneeded loader.so
	strip payloadfuser

debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o loader.so loader.c -fPIC -shared -ldl -lcrypto -lcurl -Wall -DDEBUG
	gcc -o payloadfuser payloadfuser.c -lcrypto -Wall -DDEBUG

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f loader.so
	rm -f payloadfuser
