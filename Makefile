SRC := oscode.c list.c
OUT := oscode
CFLAGS := -std=c99 -g

all: $(SRC)
	gcc $(CFLAGS) $(SRC) -o $(OUT);
    
clean: rm $(OUT)
