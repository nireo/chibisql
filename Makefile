CC = gcc
CFLAGS = -Wall -Wextra -I.
LDFLAGS =

ifdef DEBUG
CFLAGS += -g -DDEBUG
endif

BTREE_SRC = btree.c
FREELIST_SRC = freelist.c
KVSTORE_SRC = kvstore.c

BTREE_OBJ = $(BTREE_SRC:.c=.o)
FREELIST_OBJ = $(FREELIST_SRC:.c=.o)
KVSTORE_OBJ = $(KVSTORE_SRC:.c=.o)

ALL_OBJS = $(BTREE_OBJ) $(FREELIST_OBJ) $(KVSTORE_OBJ)

TEST_TARGETS = btree_test freelist_test kv_test

all: $(TEST_TARGETS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

btree_test: btree_test.c $(ALL_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

freelist_test: freelist_test.c $(ALL_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

kv_test: kv_test.c $(ALL_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(TEST_TARGETS) *.o

test: $(TEST_TARGETS)
	./btree_test
	./freelist_test
	./kv_test

.PHONY: all clean test
