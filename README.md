# CryptographyReview
Practice of cryptography algorithm

fot the bit map image encryption test, you should do as follow:
1. get a bmp file
2. exec **python imgtest.py -out [your bmp file path] ./test.h** to generate a c head file
3. exec **gcc AES.c -g -o aestool**, then **./aestool** generate crypted bit map data to out.txt
4. exec **python imgtest.py -in [your bmp file path] ./out.txt**
5. two images will show on your screen
