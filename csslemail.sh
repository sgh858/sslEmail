rm sslemail.o
gcc -c -o sslemail.o sslemail.c
gcc -o sslemail sslemail.o -lssl -lcrypto