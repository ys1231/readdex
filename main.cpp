#include <unistd.h>

//
// Created by iyue on 2022/7/10.
// di次打开  2022/7/12。
//

#include"readDex.h"


int main(int argc, char *argv[]) {


//    FILE * file = fopen("../resources/bittest","rb");
//    unsigned char * ptr = new unsigned char[2];
////    unsigned char  ptr = 0xb6 ;
////    unsigned char  ptr1 = 0x63 ;
////    fwrite(&ptr,1,1,file);
////    fwrite(&ptr1,1,1,file);
//    fread(ptr,2,1,file);
//    fclose(file);
//
//    Uleb128 uleb128(ptr);
//    int size = 0;
//    unsigned char moveBit=0;
//    uleb128.getSize(&size, moveBit);
//    uleb128.getSize(&size, moveBit,moveBit);
//    uleb128.getSize(&size, moveBit,moveBit);
//
//    return 0 ;
//





//    char str[256]={0};
//    getcwd(str,265);
//    std::cout<<str<<std::endl;
    cout << "argc:" << argc << endl;
    for (int i = 0; i < argc; ++i) {
        cout << "argv" << "[" << i << "]:" << argv[i] << endl;
    }
    string dexFilePath = "./classes.dex";
    if (argc > 1) {
        dexFilePath = argv[1];
    }
    readDex readdex(dexFilePath);
    readdex.analyseDexHeader();
    readdex.analyseStrings();
    readdex.analyseTypeStrings();
    readdex.analyseProtoIds();
    readdex.analyseFieldIds();
    readdex.analyseMethodIds();
    readdex.analyseClassIds();

    return 0;
}