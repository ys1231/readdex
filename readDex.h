//
// Created by iyue on 2022/7/10.
// 学了很多次 直接用中文注释方便快速回顾理解

#ifndef READDEX_READDEX_H
#define READDEX_READDEX_H


#include <string>
#include <cstdio>
#include <cstdlib>
#include <istream>
#include <fstream>
#include <iostream>
using namespace std;

// 以下结构体来源于 dex_file.h  源码 android-11.0.0_r46/art/libdexfile/dex/dex_file.h
// 其它结构体位于 android-11.0.0_r46/art/libdexfile/dex/dex_file_structs.h 不同版本存在差异 可通过一些关键字全局搜索
// 官方文档 https://source.android.com/devices/tech/dalvik/dex-format  其实挺全 但是相对散乱
// 文件头结构体
static constexpr size_t kSha1DigestSize = 20;
typedef struct _DexHeader {
    uint8_t  magic_[8] = {};        // 1. 魔数 文件标识的版本号 8个字节
    uint32_t checksum_ = 0;         // 2. 文件校验码 alder32 算法
    uint8_t  signature_[kSha1DigestSize] = {}; // 3. 文件签名去除前三个 SHA-1算法
    uint32_t file_size_ = 0;         // 4. dex文件长度 单位字节
    uint32_t header_size_ = 0;      // 5. dex文件头大小 (默认0x70)
    uint32_t endian_tag_ = 0;       // 6. 文件大小端标签 (标准为小端一般固定为 0x 12345678)
    uint32_t link_size_ = 0;        // 7. 链接数据的大小
    uint32_t link_off_ = 0;         // 8. 链接数据的偏移
    uint32_t map_off_ = 0;          // 9. map list 里除了对素引区和数据区的偏移地址又一次描述， 也有其他诸如 HEAD ITEM、 DEBUG INFO ITEM 等信息。
    uint32_t string_ids_size_ = 0;  // 10. dex中所有字符串内容的 个数
    uint32_t string_ids_off_ = 0;   // 11. 保存的是 偏移 其它数据结构通过索引 来访问字符串池
    uint32_t type_ids_size_ = 0;    // 12. dex中的类型数据结构的个数
    uint32_t type_ids_off_ = 0;     // 13. 偏移 比如类类型,基本类型等信息
    uint32_t proto_ids_size_ = 0;   // 14. dex中元数据信息数据结构的个数
    uint32_t proto_ids_off_ = 0;    // 15. 偏移 比如方法的返回类型,参数类型等信息
    uint32_t field_ids_size_ = 0;    // 16. dex中字段信息的 数据结构 个数
    uint32_t field_ids_off_ = 0;     // 17. 偏移
    uint32_t method_ids_size_ = 0;  // 18. dex中方法信息数据结构的大小
    uint32_t method_ids_off_ = 0;   // 29. 偏移
    uint32_t class_defs_size_ = 0;  // 20. dex中类信息数据结构的大小
    uint32_t class_defs_off_ = 0;   // 21. 偏移 内部层次很深 包含很多其它数据结构
    uint32_t data_size_ = 0;        // 22. dex中数据区域的结构信息的大小
    uint32_t data_off_ = 0;         // 23. 偏移 比如定义的常量值等信息
}DexHeader,*PDexHeader;

// 方法参数返回值等结构体
typedef struct _ProtoIdsItem
{
    uint32_t shorty_idx = 0;			// 1. 索引string
    uint32_t return_type_idx = 0;		// 2. 索引type
    uint32_t parameters_off = 0;		// 3. 偏移 里面是 4字节个数 和 2字节下标数组  0 表示没有参数
}ProtoIdsItem,*PProtoIdsItem;

// 字段属性结构体
typedef struct _FiledIdsItem
{
    u_short class_idx;				// 1. 表示本Filed所属class类型 是 type_ids index
    u_short type_idx;				// 2. 表示本Field的类型 是 type_ids index
    uint32_t name_idx;				// 3. 表示本Field的名称 是 string index

}FieldIdsItem,*PFieldIdsItem;

// 方法信息结构体
typedef struct _MethodIdsItem
{
    u_short class_idx;				// 1. 该method所属class类型 type_ids index
    u_short proto_idx;				// 2. 该method的原型  Proto_Ids index
    uint32_t name_idx;				// 3. 该method名称    String_Ids index
}MethodIdsItem,*PMethodIdsItem;




class readDex {
public:
    readDex();
    readDex(string dexFilePath);
    bool openFile(string dexFilePath="resources/classes.dex");
    virtual ~readDex();
private:
    // 文件路径
    string m_dexFilePath;
    // 文件头指针
    PDexHeader m_pDexHeader;
    // 文件内存首地址
    char * m_pBuff;
    // 字符串索引首地址
    uint32_t * m_pStringIds;
    // 类型字符串索引首地址
    int * m_pTypeIds;
    // 方法原型索引首地址
    PProtoIdsItem m_pProtoIdsItem;
    // 字段属性索引首地址
    PFieldIdsItem m_pFieldIdsItem;
    // 方法信息索引首地址
    PMethodIdsItem m_pMethodIdsItem;
public:
    // 分析文件头
    bool analyseDexHeader();
    // 分析所有字符串信息
    bool analyseStrings();
    // 分析所有类型字符串信息
    bool analyseTypeStrings();
    // 分析方法参数返回值名字信息
    bool analyseProtoIds();
    // 分析所有字段信息
    bool analyseFieldIds();
    // 分析所有方法信息
    bool analyseMethodIds();
private:
    // 索引字符串偏移地址    默认隐藏中文+序号
    char *  indexString(int index,bool hide = true);
    // 索引类型字符串
    char * indexType(int index,bool hide = true);
    // 索引方法参数返回值名字
    char * indexProtoIds(int index,bool hide = true);
};


#endif //READDEX_READDEX_H
