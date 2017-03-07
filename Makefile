all:
	cc *.c -framework IOKit -m32 -pagezero_size,0 -o pegasus_kernel
clean:
	rm -rf pegasus_kernel
