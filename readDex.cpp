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
    m_pBuff = new char(fileSize + 1);
    f.read(m_pBuff, fileSize);
    if ( f.gcount() == fileSize){
        cout<<"file read souccess!"<<endl;
    }
    f.close();

    m_pDexHeader = (PDexHeader)m_pBuff;
    // 获取String在内存中的偏移
    int offset = m_pDexHeader->string_ids_off_;
    // 获取字符串索引首地址
    m_pStringIds = (uint32_t *)(m_pBuff + offset);
    // 获取类型字符串索引首地址
    m_pTypeIds = (int *)(m_pDexHeader->type_ids_off_ + m_pBuff);
    // 方法原型首地址
    m_pProtoIdsItem = (PProtoIdsItem)(m_pDexHeader->proto_ids_off_ + m_pBuff);
    return false;
}

readDex::~readDex() {
    if(m_pBuff){
        delete [] m_pBuff;
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
 * 根据索引返回相应字符串  leb128  最多为5个字节 不定长度 android-11.0.0_r46/art/libartbase/base/leb128.h  inline
 * @param index 索引
 * @param hide 方便其它函数索引不需要打印字符串时使用
 */
char* readDex::indexString(int index,bool hide) {
    // 单个字符在内存中的位置=单个字符串偏移[索引字符串] + 内存首地址
    char* stringoff = ( char*)(m_pBuff + m_pStringIds[index]);
    // 获取每一个字符串所占多少字节 第一个字节表示整个字符串所占多少字节
    //const int size = *(stringoff);  每个字符串第一个字节为整个字符串长度 这里用特性\0结尾解析 获取字符串 -- bug 以\0结尾原理 异常就完蛋
    char* str = (char*)(stringoff + 1);
    // 隐藏对应的字符串 默认隐藏
    if (!hide)
        printf("第%d个:\t%s\n", index, str);
    else
        printf("%s", str);
    return str;
}

char *readDex::indexType(int index,bool hide) {
    // 根据type偏移得到 字符串池下标 传入 字符串池 索引对应字符
    return indexString(m_pTypeIds[index],hide);
}


bool readDex::analyseStrings() {
    // 根据文件头 字符串个数  索引类型字符串池 获取全部字符串
    for (int i = 0; i < m_pDexHeader->string_ids_size_; ++i) {
        indexString(i, false);
    }
    return true;
}

bool readDex::analyseTypeStrings() {
    // 根据文件头 typesize  个数 索引类型字符串池 获取全部类型字符串
    for (int i = 0; i < m_pDexHeader->type_ids_size_; ++i) {
        indexType(i);
    }
    return true;
}


bool readDex::analyseProtoIds() {

    for (int i = 0; i < m_pDexHeader->proto_ids_size_; ++i) {
        printf("%s\n",indexProtoIds(i));
    }

    return true;
}

char *readDex::indexProtoIds(int index,bool hide) {

    string protoAll;
    // 解析返回值类型
   // cout << "Return type:";
    protoAll += indexType(m_pProtoIdsItem[index].return_type_idx,hide);
    // 解析method原型
    //cout << "Method:";
    protoAll += indexString(m_pProtoIdsItem[index].shorty_idx,hide);

    // 判断有没有参数
    if (m_pProtoIdsItem[index].parameters_off) {
        // 获取TypeList 首地址
        int* TypeListOff = (int *)(m_pProtoIdsItem[index].parameters_off + m_pBuff);
        // 解析参数个数和参数类型
       // cout << "VelueSize:" << *TypeListOff << endl;
        // 前4个字节 表示 这个方法有几个参数 后面是 short 类型 typeids的下标
        short* index = (short*)(TypeListOff + 1);
        for (uint32_t i = 0; i < *TypeListOff; i++) {
           // cout << "velue:";
            protoAll += indexType(*index,hide);
            index++;
        }
    }
        //cout << "VelueSize: null \n";

    return const_cast<char *>(protoAll.c_str());

}





