CFLAGS = -Wall -g -std=c99
CC = gcc
TARGET = main
SOURCES = *.c

all: $(SOURCES)
	@$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	@rm -f *.o *.d  $(TARGET)
