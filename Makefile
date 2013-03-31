CC=cl
CFLAGS=/nologo 
OBJ_PARSER=parser.tab.obj parser.yy.obj
OBJ=main.obj utils-win.obj
TARGET=mini-shell.exe
SRC=main.c utils-win.c

build: $(TARGET)

$(TARGET): $(OBJ) $(OBJ_PARSER)
	$(CC) $(CFLAGS) $(OBJ) $(OBJ_PARSER) /Fe$(TARGET)

main.obj: main.c
	$(CC) $(FLAGS) /Fomain.obj /c main.c
	
utils-win.obj: utils-win.c
	$(CC) $(FLAGS) /Foutils-win.obj /c utils-win.c
	
parser.tab.obj: parser.tab.c
	$(CC) $(FLAGS) /Foparser.tab.obj /c parser.tab.c
	
parser.yy.obj: parser.yy.c
	$(CC) $(FLAGS) /Foparser.yy.obj /c parser.yy.c
clean:
	rm -rf $(OBJ) $(OBJ_PARSER) $(TARGET) *~
