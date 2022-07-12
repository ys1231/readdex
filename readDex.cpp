//
// Created by iyue on 2022/7/10.
//


#include "readDex.h"

readDex::readDex() {

}

readDex::readDex(std::string dexFilePath) {
    openFile(dexFilePath);
}

/*！
 *  打开文件
 *  dexFilePath : 文件路径
 * */
bool readDex::openFile(std::string dexFilePath) {

    if (dexFilePath.empty()){
        return false;
    }

    fstream f;
    f.open(dexFilePath.c_str(),ios::in|ios::binary);
    if(!f.is_open()){
        cout<<"open file fail!"<<endl;
    }
    f.seekp(0,ios_base::end);
    long fileSize = f.tellp();
    f.seekp(0,ios_base::beg);
    cout<<"file size:"<<fileSize<<endl;
    m_buff = new char(fileSize+1);
    f.read(m_buff,fileSize);
    if ( f.gcount() == fileSize){
        cout<<"file read souccess!"<<endl;
    }
    f.close();

    m_pDexHeader = (PDexHeader)m_buff;
    // 1. 获取String在内存中的偏移
    int offset = m_pDexHeader->string_ids_off_;
    // 2. 获取String类型的个数
    int stringSize = m_pDexHeader->string_ids_size_;
    // 3. 获取字符串索引首地址
    m_string_ids = (uint32_t *)(m_buff + offset);

    return false;
}

readDex::~readDex() {
    if(m_buff){
        delete [] m_buff;
    }
    cout<<"The program is over."<<endl;
}

/*!
 * 分析文件头
 * @return
 */
bool readDex::analyseDexHeader() {

    cout << "start anlisys:" << endl;
    cout << "magic:" << m_pDexHeader->magic_ << endl;
    cout << "checksum:" << hex<<m_pDexHeader->checksum_ << endl;
    cout << "signature:0x";
    for (int i=0;i<kSha1DigestSize;++i)
        printf("%X",m_pDexHeader->signature_[i]);
    cout<< endl;
    cout << "fileSize:" << m_pDexHeader->file_size_ << endl;
    cout << "headerSize:" << m_pDexHeader->header_size_ << endl;
    cout << "endanTag:" << m_pDexHeader->endian_tag_ << endl;
    cout << "linkSize:" << m_pDexHeader->link_size_ << endl;
    cout << "linkOff:" << m_pDexHeader->link_off_ << endl;
    cout << "mapOff:" << m_pDexHeader->map_off_<< endl;
    cout << "stringIdsSize:" << m_pDexHeader->string_ids_size_ << endl;
    cout << "stringIdsOff:" << m_pDexHeader->string_ids_off_ << endl;
    cout << "typeIdsSize:" << m_pDexHeader->type_ids_size_ << endl;
    cout << "typeIdsOff:" << m_pDexHeader->type_ids_off_ << endl;
    cout << "protoIdsSize:" << m_pDexHeader->proto_ids_size_ << endl;
    cout << "protoIdsOff:" << m_pDexHeader->proto_ids_off_ << endl;
    cout << "fieldIdsSize:" << m_pDexHeader->field_ids_size_ << endl;
    cout << "fieldIdsOff:" << m_pDexHeader->field_ids_off_ << endl;
    cout << "methodIdsSize:" << m_pDexHeader->method_ids_size_ << endl;
    cout << "methodIdsOff:" << m_pDexHeader->method_ids_off_ << endl;
    cout << "classDefsSize:" << m_pDexHeader->class_defs_size_<< endl;
    cout << "classDefsOff:" << m_pDexHeader->class_defs_off_ << endl;
    cout << "dataSize:" << m_pDexHeader->data_size_ << endl;
    cout << "dateOff:" << m_pDexHeader->data_off_ << endl;
    return true;
}

/*!
 * 根据索引返回相应字符串
 * @param index 索引
 */
char* readDex::indexString(int index,bool hide) {
    // 单个字符在内存中的位置=单个字符串偏移[索引字符串] + 内存首地址
    char* stringoff = ( char*)(m_buff + m_string_ids[index]);
    // 获取每一个字符串所占多少字节 第一个字节表示整个字符串所占多少字节
    const int size = *(stringoff);
    // 获取字符串 -- bug 以\0结尾原理 异常就完蛋
    char* str = (char*)(stringoff + 1);
    // 显示对应的字符串 默认显示
    if (!hide)
        printf("第%d个:\t%s\n", index, str);
    else
        printf("\t%s\n", str);
    return str;
}

bool readDex::analyseStrings() {
    for (int i = 0; i < m_pDexHeader->string_ids_size_; ++i) {
        indexString(i);
    }
    return false;
}


