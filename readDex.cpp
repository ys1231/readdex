//
// Created by iyue on 2022/7/10.
//


#include "readDex.h"
#include"sourceh/modifiers.h"
#include "myuleb128.h"

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

    if (dexFilePath.empty()) {
        return false;
    }

    fstream f;
    f.open(dexFilePath.c_str(), ios::in | ios::binary);
    if (!f.is_open()) {
        cout << "open file fail!" << endl;
    }
    f.seekp(0, ios_base::end);
    long fileSize = f.tellp();
    f.seekp(0, ios_base::beg);
    cout << "file size:" << fileSize << endl;
    m_pBuff = new char[++fileSize];
    f.read(m_pBuff, fileSize);
    if (f.gcount() == fileSize) {
        cout << "file read souccess!" << endl;
    }
    f.close();

    m_pDexHeader = (PDexHeader) m_pBuff;
    // 获取String在内存中的偏移
    int offset = m_pDexHeader->string_ids_off_;
    // 获取字符串索引首地址
    m_pStringIds = (uint32_t *) (m_pBuff + offset);
    // 获取类型字符串索引首地址
    m_pTypeIds = (int *) (m_pDexHeader->type_ids_off_ + m_pBuff);
    // 方法原型首地址
    m_pProtoIdsItem = (PProtoIdsItem) (m_pDexHeader->proto_ids_off_ + m_pBuff);
    // 字段属性首地址
    m_pFieldIdsItem = (PFieldIdsItem) (m_pDexHeader->field_ids_off_ + m_pBuff);
    // 方法信息首地址
    m_pMethodIdsItem = (PMethodIdsItem) (m_pDexHeader->method_ids_off_ + m_pBuff);
    // 类信息偏移首地址
    m_pClassDefsItem = (PClassDefsItem) (m_pDexHeader->class_defs_off_ + m_pBuff);
    return false;
}

readDex::~readDex() {
    if (m_pBuff) {
        delete[] m_pBuff;
    }
    cout << "The program is over." << endl;
}

/*!
 * 分析文件头
 * @return
 */
bool readDex::analyseDexHeader() {

    cout << "start anlisys:" << endl;
    cout << "magic:" << m_pDexHeader->magic_ << endl;
    cout << "checksum:" << hex << m_pDexHeader->checksum_ << endl;
    cout << "signature:0x";
    for (int i = 0; i < kSha1DigestSize; ++i)
        printf("%X", m_pDexHeader->signature_[i]);
    cout << endl;
    cout << "fileSize:" << m_pDexHeader->file_size_ << endl;
    cout << "headerSize:" << m_pDexHeader->header_size_ << endl;
    cout << "endanTag:" << m_pDexHeader->endian_tag_ << endl;
    cout << "linkSize:" << m_pDexHeader->link_size_ << endl;
    cout << "linkOff:" << m_pDexHeader->link_off_ << endl;
    cout << "mapOff:" << m_pDexHeader->map_off_ << endl;
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
    cout << "classDefsSize:" << m_pDexHeader->class_defs_size_ << endl;
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
char *readDex::indexString(int index, bool hide) {
    if (index > m_pDexHeader->string_ids_size_) {
        printf("The index is beyond the maximum range.\n");
        return (char *)"index fail!";
    }

    // 单个字符在内存中的位置=单个字符串偏移[索引字符串] + 内存首地址
    char *stringoff = (char *) (m_pBuff + m_pStringIds[index]);
    // 获取每一个字符串所占多少字节 第一个字节表示整个字符串所占多少字节
    //const int size = *(stringoff);  每个字符串第一个字节为整个字符串长度 这里用特性\0结尾解析 获取字符串 -- but 以\0结尾原理 异常就完蛋
    char *str = (char *) (stringoff + 1);
    // 隐藏对应的字符串 默认隐藏
    if (!hide)
        printf("第%d个:\t%s\n", index, str);
    else
        printf(" %s\n", str);
    return str;
}

char *readDex::indexType(int index, bool hide) {
    if (index > m_pDexHeader->type_ids_size_) {
        printf("The index is beyond the maximum range.\n");
        return (char *)"index fail!";
    }
    // 根据type偏移得到 字符串池下标 传入 字符串池 索引对应字符
    return indexString(m_pTypeIds[index], hide);
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
        printf("%s\n", indexProtoIds(i));
    }

    return true;
}

char *readDex::indexProtoIds(int index, bool hide) {

    /*
	 * method:方法原型 string index
	 * return:返回值类型 type index
	 * parameters_off arg; 参数信息
	 */

    if (index > m_pDexHeader->proto_ids_size_) {
        printf("The index is beyond the maximum range.\n");
        return (char *)"index fail!";
    }
    string protoAll;
    // 解析返回值类型
    // cout << "Return type:";
    protoAll += indexType(m_pProtoIdsItem[index].return_type_idx, hide);
    // 解析method原型
    //cout << "Method:";
    protoAll += indexString(m_pProtoIdsItem[index].shorty_idx, hide);

    // 判断有没有参数
    if (m_pProtoIdsItem[index].parameters_off) {
        // 获取TypeList 首地址
        int *TypeListOff = (int *) (m_pProtoIdsItem[index].parameters_off + m_pBuff);
        // 解析参数个数和参数类型
        // cout << "VelueSize:" << *TypeListOff << endl;
        // 前4个字节 表示 这个方法有几个参数 后面是 short 类型 typeids的下标
        short *index = (short *) (TypeListOff + 1);
        for (uint32_t i = 0; i < *TypeListOff; i++) {
            // cout << "velue:";
            protoAll += indexType(*index, hide);
            index++;
        }
    }
    //cout << "VelueSize: null \n";

    return const_cast<char *>(protoAll.c_str());

}

char *readDex::indexFieldIds(int index, bool hide) {
    string tmp;
    cout << "本Field所属class:";
    tmp += "本Field所属class: ";
    tmp += indexType(m_pFieldIdsItem[index].class_idx);
    cout << "本Field的类型:";
    tmp += " 本Field的类型: ";
    tmp += indexType(m_pFieldIdsItem[index].type_idx);
    cout << "本Field的名称:";
    tmp += " 本Field的名称: ";
    tmp += indexString(m_pFieldIdsItem[index].name_idx);
    return const_cast<char *>(tmp.c_str());
}

char *readDex::indexMethodIds(int index, bool hide) {
    string tmp;
    cout << "该method所属class类型:";
    tmp += " 该method所属class类型: ";
    tmp += indexType(m_pMethodIdsItem[index].class_idx);
    cout << "该method的原型:";
    tmp += " 该method的原型: ";
    tmp += indexProtoIds(m_pMethodIdsItem[index].proto_idx);
    cout << "该method名称:";
    tmp += " 该method名称: ";
    tmp += indexString(m_pMethodIdsItem[index].name_idx);

    return const_cast<char *>(tmp.c_str());
}

bool readDex::analyseFieldIds() {
    /*
	 * // 1. 表示本Filed所属class类型 是 type_ids index
	 * // 2. 表示本Field的类型 type_ids index
	 * // 3. 表示本Field的名称 string_ids index
	 */

    for (uint32_t i = 0; i < m_pDexHeader->field_ids_size_; i++) {
        cout << "第" << i << "个Filed" << endl;
        cout << "本Field所属class:";
        indexType(m_pFieldIdsItem[i].class_idx);
        cout << "本Field的类型:";
        indexType(m_pFieldIdsItem[i].type_idx);
        cout << "本Field的名称:";
        indexString(m_pFieldIdsItem[i].name_idx);

    }

    return true;
}

bool readDex::analyseMethodIds() {
    /*
	 *	class_idx;				// 1. 该method所属class类型 type_ids index
	 * 	proto_idx;				// 2. 该method的原型  Proto_Ids index
	 * 	name_idx;				// 3. 该method名称    String_Ids index
	 */
    for (uint32_t i = 0; i < m_pDexHeader->method_ids_size_; i++) {
        cout << "第" << i << "个Method" << endl;
        cout << "该method所属class类型:";
        indexType(m_pMethodIdsItem[i].class_idx);
        cout << "该method的原型:";
        indexProtoIds(m_pMethodIdsItem[i].proto_idx);
        cout << "该method名称:";
        indexString(m_pMethodIdsItem[i].name_idx);
    }
    return true;

}

void readDex::indexClassDefs(int index, bool hide) {

    /**
     *  class_idx_;        // 1. 必须是class类型值 是 type_ids index
        access_flags_;      // 2. 描述 class 的访问类型,诸如 public、 final、 static 等.  直接调用系统解析函数 art::PrettyJavaAccessFlags(uint32_t access_flags) android-11.0.0_r46/art/libdexfile/dex/modifiers.cc
        superclass_idx_;   // 3. 索引到superclass 是 type_ids index
        interfaces_off_;   // 4. 值为偏移地址,指向 class 的 interfaces,被指向的数据结构为 type_list.  class 若没有 interfaces,值为0.  从解析这个开始建议直接看官网 没有什么资料比官网更加详细
        source_file_idx_;   // 5. 表示源代码文件的信息，值是 string_ ids 的一个 index。若此项信息缺失，此项值赋值为 NO_INDEX=0xFFFF FFFF
        annotations_off_;  // 6. 类的注释信息 位置在data区 值为 annotations_directory_item 若没有则为0
        class_data_off_;   // 7. 内容指向该class 用到的数据 位置在data区 格式为 class_data_item 没有为0  内容很多 详细描述该 class 的 field、 method、 method 里的执行代码等信息
        static_values_off_;// 8. 偏移地址,指向 data 区里的一个列表（list),格式为 encoded_array_item. 若没有为0.
     */

    cout << "class_idx: " << m_pClassDefsItem[index].class_idx_;
    indexType(m_pClassDefsItem[index].class_idx_);

    cout << "access_flags: " << m_pClassDefsItem[index].access_flags_
         << art::PrettyJavaAccessFlags(m_pClassDefsItem[index].access_flags_) << endl;

    cout << "superclass_idx: " << m_pClassDefsItem[index].superclass_idx_;
    indexType(m_pClassDefsItem[index].superclass_idx_);

    // class 若没有 interfaces,值为0
    cout << "interfaces_off: " << m_pClassDefsItem[index].interfaces_off_ << " ";
    if (m_pClassDefsItem[index].interfaces_off_) {
        PTypeList tmpTypeList = (PTypeList) (m_pClassDefsItem[index].interfaces_off_ + m_pBuff);
        for (int i = 0; i < tmpTypeList->size; ++i) {
            indexType(tmpTypeList->type_idx_list[i]);
        }
    } else
        cout << endl;

    cout << "source_file_idx: " << m_pClassDefsItem[index].source_file_idx_;
    indexString(m_pClassDefsItem[index].source_file_idx_);

    //  annotations_off_ 好像暂时用不到
    cout << "annotations_off: " << m_pClassDefsItem[index].annotations_off_ << endl;

    cout << "class_data_off: " << m_pClassDefsItem[index].class_data_off_;
    /**
        uleb128 static_fields_size;        // 此项中定义的静态字段的数量
        uleb128 instance_fields_size;    // 此项中定义的实例字段的数量
        uleb128 direct_methods_size;    // 此项中定义的直接方法的数量
        uleb128 virtual_methods_size;   // 此项中定义的虚拟方法的数量
        encoded_field static_fields[static_fields_size];    // 定义的静态字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
        encoded_field instance_fields[instance_fields_size];    // 定义的实例字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
        encoded_method direct_methods[direct_methods_size];    // 定义的直接（static、private 或构造函数的任何一个）方法；以一系列编码元素的形式表示。这些方法必须按 method_idx 以升序进行排序。
        encoded_method virtual_methods[virtual_methods_size];    // 定义的虚拟（非 static、private 或构造函数）方法；以一系列编码元素的形式表示。这些方法必须按 method_idx 以升序进行排序。。
     */
    uchar * addr = (reinterpret_cast<uchar *>(m_pClassDefsItem[index].class_data_off_ + m_pBuff));
    unsigned char moveBit=0;
    int static_fields_size =0;
    myDecodeUleb128(addr,&static_fields_size,moveBit);
    int instance_fields_size =  0 ;
    myDecodeUleb128(addr,&instance_fields_size,moveBit,moveBit);
    int direct_methods_size =0;
    myDecodeUleb128(addr,&direct_methods_size,moveBit,moveBit);
    int virtual_methods_size = 0;
    myDecodeUleb128(addr,&virtual_methods_size,moveBit,moveBit);
    // TODO 获取到参数后索引对应index 即可
    // indexFieldIds
    // indexMethodIds
    cout << "static_values_off_: " << m_pClassDefsItem[index].static_values_off_<<endl;

}

bool readDex::analyseClassIds() {
 // TODO 可直接调用 indexClassDefs 根据下标索引
    return false;
}









