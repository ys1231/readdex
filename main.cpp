#include <unistd.h>

//
// Created by iyue on 2022/7/10.
// di次打开  2022/7/12。
//

#include"readDex.h"


int main(int argc, char *argv[]) {

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
    readdex.indexClassDefs(318);
    return 0;
}