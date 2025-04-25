# Makefile for pt_walk project

# Директории
PAGEMAP_DIR = pagemap
ALLOC_DIR = alloc_test

# Компилятор и флаги
CC = gcc
CFLAGS = -O2 -Wall

# Цель по умолчанию
all: $(ALLOC_DIR)/alloc_test $(PAGEMAP_DIR)/pagemap

# Сборка твоей программы
$(ALLOC_DIR)/alloc_test: $(ALLOC_DIR)/main.c
	$(CC) $(CFLAGS) -o $@ $<

# Сборка pagemap (используем его Makefile)
$(PAGEMAP_DIR)/pagemap:
	$(MAKE) -C $(PAGEMAP_DIR) pagemap

# Очистка
clean:
	rm -f $(ALLOC_DIR)/alloc_test
	$(MAKE) -C $(PAGEMAP_DIR) clean

.PHONY: all clean
