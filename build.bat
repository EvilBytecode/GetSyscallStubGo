@echo off
title building...
gcc -c syscall_stub.c -o syscall_stub.o
ar rcs libsyscall_stub.a syscall_stub.o
go build -ldflags "-s -w" .
del libsyscall_stub.a syscall_stub.o
echo Sucessfully built
timeout /t 3 >NUL
exit