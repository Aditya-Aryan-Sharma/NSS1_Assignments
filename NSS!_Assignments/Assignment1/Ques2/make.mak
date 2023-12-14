CC = g++
CFLAGS = -std=c++11 -Wall
TARGET = sudo

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $@ $<

set_suid:
	sudo chmod u+s $(TARGET)

set_root_owner:
	sudo chown root:root $(TARGET)

