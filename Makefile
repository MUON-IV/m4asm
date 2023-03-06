all:
	gcc -o m4asm src/*.c
	./m4asm -i test.asm -o out.bin
	xxd out.bin