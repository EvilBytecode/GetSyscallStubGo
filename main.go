package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lsyscall_stub
#include "syscall_stub.h"
*/
import "C"
import "fmt"
func main() {
    C.exec()
	fmt.Scanln()
}
