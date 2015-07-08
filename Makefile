mptun : mptun.c
	gcc -o $@ $^ -g -Wall

clean :
	rm mptun