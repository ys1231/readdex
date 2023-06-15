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
        return (char *) "index fail!";
    }

    // 单个字符在内存中的位置=单个字符串偏移[索引字符串] + 内存首地址
    char *stringoff = (char *) (m_pBuff + m_pStringIds[index]);
    // 获取每一个字符串所占多少字节 第一个字节表示整个字符串所占多少字节
    //const int size = *(stringoff);  每个字符串第一个字节为整个字符串长度 这里用特性\0结尾解析 获取字符串 -- but 以\0结尾原理 异常就完蛋
    // 关于此格式 https://source.android.com/devices/tech/dalvik/dex-format?hl=zh-cn#string-data-item
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
        return (char *) "index fail!";
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
        return (char *) "index fail!";
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

    if (index > m_pDexHeader->field_ids_size_) {
        return nullptr;
    }
    string tmp;
    tmp += "本Field所属class: ";
    tmp += indexType(m_pFieldIdsItem[index].class_idx);
    tmp += " 本Field的类型: ";
    tmp += indexType(m_pFieldIdsItem[index].type_idx);
    tmp += " 本Field的名称: ";
    tmp += indexString(m_pFieldIdsItem[index].name_idx);
    cout << tmp << endl;
    return const_cast<char *>(tmp.c_str());
}

char *readDex::indexMethodIds(int index, bool hide) {

    if (index > m_pDexHeader->method_ids_size_) {
        return nullptr;
    }
    string tmp;
    tmp += " 该method所属class类型: ";
    tmp += indexType(m_pMethodIdsItem[index].class_idx);
    tmp += " 该method的原型: ";
    tmp += indexProtoIds(m_pMethodIdsItem[index].proto_idx);
    tmp += " 该method名称: ";
    tmp += indexString(m_pMethodIdsItem[index].name_idx);
    cout << tmp;
    return const_cast<char *>(tmp.c_str());
}

string readDex::indexMethodName(int index) {
    return indexString(m_pMethodIdsItem[index].name_idx);
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

bool readDex::analyseClassIds() {
    // TODO 可直接调用 indexClassDefs 根据下标索引
    indexClassDefs(1964);
    return false;
}

void readDex::indexClassDefs(int index, bool hide) {

    /**
     * class_def_item
     *  class_idx_;        // 1. 必须是class类型值 是 type_ids index
        access_flags_;      // 2. 描述 class 的访问类型,诸如 public、 final、 static 等.  直接调用系统解析函数 art::PrettyJavaAccessFlags(uint32_t access_flags) android-11.0.0_r46/art/libdexfile/dex/modifiers.cc
        superclass_idx_;   // 3. 索引到superclass 是 type_ids index
        interfaces_off_;   // 4. 值为偏移地址,指向 class 的 interfaces,被指向的数据结构为 type_list.  class 若没有 interfaces,值为0.  从解析这个开始建议直接看官网 没有什么资料比官网更加详细
        source_file_idx_;   // 5. 表示源代码文件的信息，值是 string_ ids 的一个 index。若此项信息缺失，此项值赋值为 NO_INDEX=0xFFFF FFFF
        annotations_off_;  // 6. 类的注释信息 位置在data区 值为 annotations_directory_item 若没有则为0
        class_data_off_;   // 7. 内容指向该class 用到的数据 位置在data区 格式为 class_data_item 没有为0  内容很多 详细描述该 class 的 field、 method、 method 里的执行代码等信息
        static_values_off_;// 8. 偏移地址,指向 data 区里的一个列表（list),格式为 encoded_array_item. 若没有为0.
     */
    cout << "\n------------------class_def_item-------------" << endl;
    cout << "class_idx: " << m_pClassDefsItem[index].class_idx_;
    indexType(m_pClassDefsItem[index].class_idx_);

    cout << "access_flags: " << m_pClassDefsItem[index].access_flags_
         << " "
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

    // 关键数据 类的字段 方法信息都在这里
    cout << "class_data_off: " << m_pClassDefsItem[index].class_data_off_;

    /**
     * class_data_item 引用自 class_def_item 出现在 data 区段中 对齐：无（字节对齐
     * uleb128 static_fields_size;        // 此项中定义的静态字段的数量
     * uleb128 instance_fields_size;    // 此项中定义的实例字段的数量
     * uleb128 direct_methods_size;    // 此项中定义的直接方法的数量
     * uleb128 virtual_methods_size;   // 此项中定义的虚拟方法的数量
     * encoded_field static_fields[static_fields_size];    // 定义的静态字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
     * encoded_field instance_fields[instance_fields_size];    // 定义的实例字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
     * encoded_method direct_methods[direct_methods_size];    // 定义的直接（static、private 或构造函数的任何一个）方法；以一系列编码元素的形式表示。这些方法必须按 method_idx 以升序进行排序。
     * encoded_method virtual_methods[virtual_methods_size];    // 定义的虚拟（非 static、private 或构造函数）方法；以一系列编码元素的形式表示。这些方法必须按 method_idx 以升序进行排序。。
     */
    char *addr = reinterpret_cast<char *>(m_pClassDefsItem[index].class_data_off_ + m_pBuff);
    uint32_t offset = 0;

    uint32_t static_fields_size = 0;
    DecodeUleb128(addr, static_fields_size, offset);

    uint32_t instance_fields_size = 0;
    DecodeUleb128(addr, instance_fields_size, offset);

    uint32_t direct_methods_size = 0;
    DecodeUleb128(addr, direct_methods_size, offset);

    uint32_t virtual_methods_size = 0;
    DecodeUleb128(addr, virtual_methods_size, offset);

    // 在读取类的字段和方法时需要注意 第一次索引为对应 ids的偏移 但是 之后 就是前一个索引的差值
    // https://source.android.com/docs/core/dalvik/dex-format?hl=zh-cn#encoded-field-format
    // 原文 : 此字段标识（包括名称和描述符）的 field_ids 列表中的索引；它会表示为与列表中前一个元素的索引之间的差值。列表中第一个元素的索引则直接表示出来。
    // 因此字段和方法都需要记录偏移
    // 下面4个方法一个都不能少
    uint32_t iFieldIndex = 0;
    analyseEncodedField(addr, static_fields_size, offset, iFieldIndex);
    analyseEncodedField(addr, instance_fields_size, offset, iFieldIndex);

    uint32_t iMethodIndex = 0;
    analyseEncodedMethod(addr, direct_methods_size, offset, iMethodIndex);
    analyseEncodedMethod(addr, virtual_methods_size, offset, iMethodIndex);
    cout << "static_values_off_: " << m_pClassDefsItem[index].static_values_off_ << endl;

}

/**
 *
 * @param addr 某个类的ClassDefsItem结构体的起始位置
 * @param fieldSize 实际的字段个数
 * @param offset  当前可变数据的起始偏移地址
 * @param mieldIndex  记录上一个字段的索引
 * @return
 */
uint32_t readDex::analyseEncodedField(const char *addr, uint32_t fieldSize, uint32_t &offset, uint32_t &mieldIndex) {
    /**
     * encoded_field 格式
     * 名称	格式 说明
     * field_idx_diff	uleb128	此字段标识（包括名称和描述符）的 field_ids 列表中的索引；它会表示为与列表中前一个元素的索引之间的差值。列表中第一个元素的索引则直接表示出来。
     * access_flags	uleb128	字段的访问标志（public、final 等）。如需了解详情，请参阅“access_flags 定义”。
    */
    if (!fieldSize)
        return 0;
    cout << "\n------------------encoded_field-------------" << endl;

    // class_data_item 是不对齐内存的 是一段连续内存
    // 解码后 的字段基于 field_ids 列表中的索引
    uint32_t index = 0;

    for (int i = 0; i < fieldSize; ++i) {
        // field_idx_diff
        DecodeUleb128(addr, index, offset);
        mieldIndex += index;
        indexFieldIds(mieldIndex);

        // access_flags
        DecodeUleb128(addr, index, offset);
        cout << "access_flags: " << index << " " << art::PrettyJavaAccessFlags(index) << endl;
    }
    return offset;
}

/**
 *
 * @param addr 某个类的ClassDefsItem结构体的起始位置
 * @param fieldSize 实际的方法个数
 * @param offset  当前可变数据的起始偏移地址
 * @param methodIndex  记录上一个方法索引
 * @return
 */
uint32_t readDex::analyseEncodedMethod(const char *addr, uint32_t methodSize, uint32_t &offset, uint32_t methodIndex) {
    /**
     * encoded_method 格式
     * 名称	格式	说明
     * method_idx_diff	uleb128	此方法标识（包括名称和描述符）的 method_ids 列表中的索引；它会表示为与列表中前一个元素的索引之间的差值。列表中第一个元素的索引则直接表示出来。
     * access_flags	uleb128	方法的访问标志（public、final 等）。如需了解详情，请参阅“access_flags 定义”。
     * code_off	uleb128	从文件开头到此方法的代码结构的偏移量；如果此方法是 abstract 或 native，则该值为 0。偏移量应该是到 data 区段中某个位置的偏移量。数据格式由下文的“code_item”指定。
     */
    if (!methodSize)
        return 0;
    cout << "\n------------------encoded_method-------------" << endl;
    // class_data_item 是不对齐内存的 是一段连续内存
    // 解码后 的字段基于 field_ids 列表中的索引
    uint32_t index = 0;
    // 需要解码的字节个数
    uint8_t size = 3;
    //  临时保存方法名称
    string sMethodName;
    for (int i = 0; i < methodSize; ++i) {

        // method_idx_diff
        DecodeUleb128(addr, index, offset);
        methodIndex += index;
        indexMethodIds(methodIndex);
        sMethodName = indexMethodName(methodIndex);

        // access_flags
        DecodeUleb128(addr, index, offset);
        cout << "access_flags: " << index << " " << art::PrettyJavaAccessFlags(index) << endl;

        // code_off
        DecodeUleb128(addr, index, offset);
        PCode_item PCodeItem = (PCode_item) (index + m_pBuff);
        analyseCodeItem(sMethodName,PCodeItem);

    }
    return offset;
}

/**
 * @param pcodeitem 指向要解析的code_item指针
 */
void readDex::analyseCodeItem(string methodName, PCode_item pcodeitem) {
    /**
     typedef struct _code_item {
        ushort registers_size;  // 此方法使用的寄存器数量
        ushort ins_size;        // 此方法传入参数的字数
        ushort outs_size;       // 此方法进行方法调用所需的传出参数空间的字数
        ushort tries_size;      // 此实例的 try_item 数量。如果此值为非零值，则这些项会显示为 insns 数组（正好位于此实例中 tries 的后面）。
        uint debug_info_off;    // 从文件开头到此代码的调试信息（行号 + 局部变量信息）序列的偏移量；如果没有任何信息，则该值为 0。该偏移量（如果为非零值）应该是到 data 区段中某个位置的偏移量。数据格式由下文的“debug_info_item”指定。
        uint insns_size;        // 指令列表的大小（以 16 位代码单元为单位）
        ushort insns[];          // 字节码的实际数组。insns 数组中的代码格式由随附文档 Dalvik 字节码指定。请注意，尽管此项被定义为 ushort 的数组，但仍有一些内部结构倾向于采用四字节对齐方式。此外，如果此项恰好位于某个字节序交换文件中，则交换操作将只在单个 ushort 上进行，而不在较大的内部结构上进行。
        // ushort padding;         // （可选）= 0	使 tries 实现四字节对齐的两字节填充。只有 tries_size 为非零值且 insns_size 是奇数时，此元素才会存在。
        // try_item *tries;         // （可选）	用于表示在代码中捕获异常的位置以及如何对异常进行处理的数组。该数组的元素在范围内不得重叠，且数值地址按照从低到高的顺序排列。只有 tries_size 为非零值时，此元素才会存在。
        // encoded_catch_handler_list handlers; // （可选）	用于表示“捕获类型列表和关联处理程序地址”的列表的字节。每个 try_item 都具有到此结构的分组偏移量。只有 tries_size 为非零值时，此元素才会存在。
        // 最后这个涉及结构太多先不管了.
    } Code_item, *PCode_item;
     */
    if (!pcodeitem)
        return;
    cout << "---------" << methodName << " code_item -----------"<<endl;
    cout << "此方法使用的寄存器数量(registers_size): " << pcodeitem->registers_size << endl;
    cout << "此方法的传入参数的字数(ins_size): " << pcodeitem->ins_size << endl;
    cout << "此方法进行方法调用所需的传出参数空间的字数(outs_size): " << pcodeitem->outs_size << endl;
    cout << "此实例的 try_item 数量(tries_size): " << pcodeitem->tries_size << endl;
    // 暂不展开
    cout << "从文件开头到此代码的调试信息(debug_info_off): " << pcodeitem->debug_info_off << endl;
    cout << "指令列表的大小(insns_size): " << pcodeitem->insns_size << endl;
    cout << "指令0x: ";
    for (int i = 0; i < pcodeitem->insns_size; ++i) {
        cout<< pcodeitem->insns[i] << " ";
    }
    cout << endl;

}











