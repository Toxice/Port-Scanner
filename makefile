# makefile for the port scanner

CC = gcc
CFLAGS = -c
TARGET = port_scanning
OBJ = port_scanning.o

# phony flags for compiling, linking, running an cleaning
.PHONY: all runtcp runudp clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET)

$(OBJ): port_scanning.c
	$(CC) $(CFLAGS) $< -o $@

runtcp: $(TARGET)
	sudo ./$(TARGET) -a 1.1.1.1 -t tcp

runudp: (TARGET)
	sudo ./$(TARGET) -a 1.1.1.1 -t udp	

clean:
	rm $(TARGET) $(OBJ)		 	
