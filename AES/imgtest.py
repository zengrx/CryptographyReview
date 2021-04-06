import sys
from PIL import Image

def openImageFIle(path):
    img = Image.open(path)
    img.show()
    return img

def convertImage2Buf(img, path):
    pixels = img.load()
    f = open(path, "w")
    f.writelines("unsigned char pic[] = {\n")
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            line = ", ".join(map(str, pixels[i, j]))
            line = line + ",\n"
            f.writelines(line)
    f.writelines("};")

def createNewImage(img, path):
    pixels = img.load()
    f = open(path, "r")
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            line = f.readline()
            line = line.strip()
            line = line.split(',')
            line = map(int, line)
            r = line[0]
            g = line[1]
            b = line[2]
            pixels[i, j] = (r, g, b)
    img.show()
    img.save('./out.bmp')

# python imgtest.py -in ./pk.bmp ./out.txt
# python imgtest.py -out ./pk.bmp ./test.h
if __name__ == "__main__":
    myimg = openImageFIle(sys.argv[2])
    if sys.argv[1] == "-in":
        createNewImage(myimg, sys.argv[3])
    elif sys.argv[1] == "-out":
        convertImage2Buf(myimg, sys.argv[3])
    else:
        print "param err"
