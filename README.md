# PS-1
## 1- Inside ebpf folder
run clang -O2 -g -target bpf -c src/drop_port.c -o drop_port.o


## 2- Aftererwards run this 
run sudo go run usr/loader.go 


## 3- Hit it with curl 
curl localhost:4040 it won't bind as port is blocked.
curl localhost:XYZD it'll bind
