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
//#include "sourceh/leb128.h"
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
    uint32_t method_ids_size_ = 0;  // 18. dex中方法信息数据结构的个数
    uint32_t method_ids_off_ = 0;   // 29. 偏移
    uint32_t class_defs_size_ = 0;  // 20. dex中类信息数据结构的个数
    uint32_t class_defs_off_ = 0;   // 21. 偏移 内部层次很深 包含很多其它数据结构
    uint32_t data_size_ = 0;        // 22. dex中数据区域的结构信息的个数
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

// Raw class_def_item.  由头文件指向的 class结构体
/** annotations_direcotry_item 注释暂时用不上 先不管了
 * class_annotations_off	uint	从文件开头到直接在该类上所做的注释的偏移量；如果该类没有任何直接注释，则该值为 0。该偏移量（如果为非零值）应该是到 data 区段中某个位置的偏移量。数据格式由下文的“annotation_set_item”指定。
fields_size	uint	此项所注释的字段数量
annotated_methods_size	uint	此项所注释的方法数量
annotated_parameters_size	uint	此项所注释的方法参数列表的数量
field_annotations	field_annotation[fields_size]（可选）	所关联字段的注释列表。该列表中的元素必须按 field_idx 以升序进行排序。
method_annotations	method_annotation[methods_size]（可选）	所关联方法的注释列表。该列表中的元素必须按 method_idx 以升序进行排序。
parameter_annotations	parameter_annotation[parameters_size]（可选）	所关联方法参数的注释列表。该列表中的元素必须按 method_idx 以升序进行排序。
 */
typedef struct _ClassDefsItem {
    uint32_t class_idx_;        // 1. 必须是class类型值 是 type_ids index
    uint32_t access_flags_;      // 2. 描述 class 的访问类型,诸如 public、 final、 static 等.  直接调用系统解析函数 art::PrettyJavaAccessFlags(uint32_t access_flags) android-11.0.0_r46/art/libdexfile/dex/modifiers.cc
    uint32_t superclass_idx_;   // 3. 索引到superclass 是 type_ids index
    uint32_t interfaces_off_;   // 4. 值为偏移地址,指向 class 的 interfaces,被指向的数据结构为 type_list.  class 若没有 interfaces,值为0.
    uint32_t source_file_idx_;   // 5. 表示源代码文件名，值是 string_ ids 的一个 index。若此项信息缺失，此项值赋值为 NO_INDEX=0xFFFF FFFF
    uint32_t annotations_off_;  // 6. 类的注释信息 位置在data区 值为 annotations_direcotry_item 若没有则为0
    uint32_t class_data_off_;   // 7. 内容指向该class 用到的数据 位置在data区 格式为 class_data_item 没有为0  内容很多 详细描述该 class 的 field、 method、 method 里的执行代码等信息
    uint32_t static_values_off_;// 8. 偏移地址,指向 data 区里的一个列表（list),格式为 encoded_array_item. 若没有为0.
}ClassDefsItem,*PClassDefsItem;

// type_list 由上面的 interfaces_off_ 使用的结构体
typedef  struct _TypeList{
    uint size;                      // 1. 列表的大小（以条目数表示）
    ushort type_idx_list[];	        // 2. 列表的元素  大坑 官方都说了是数组结果以结构体指针去访问 浪费了好长时间一直想不明白为什么报错,固化的思维要不得!
}TypeList,*PTypeList;

// 开始 最后一步解析 class_data_item 找到阿里的  不过 并没有帮助 所以 准备移植Androidsdk dexdump的源码 解决这部份 自己写循环一个字节一个字节解析实在是麻烦和初衷不符 https://developer.aliyun.com/article/182046
// class_data_item 结构体为不定长度 就不直接定义了
/**
    uleb128 static_fields_size;		// 此项中定义的静态字段的数量
    uleb128 instance_fields_size;	// 此项中定义的实例字段的数量
    uleb128 direct_methods_size;    // 此项中定义的直接方法的数量
    uleb128 virtual_methods_size;   // 此项中定义的虚拟方法的数量
    encoded_field static_fields	[static_fields_size];	// 定义的静态字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
    encoded_field instance_fields	[instance_fields_size];	// 定义的实例字段；以一系列编码元素的形式表示。这些字段必须按 field_idx 以升序进行排序。
    encoded_method direct_methods	[direct_methods_size];	// 定义的直接（static、private 或构造函数的任何一个）方法；以一系列编码元素的形式表示。这些方法必须按 method_idx 以升序进行排序。
    encoded_method virtual_methods	[virtual_methods_size];	// 定义的虚拟（非 static、private 或构造函数）方法；以一系列编码元素的形式表示。此列表不得包括继承方法，除非被此项所表示的类覆盖。
                                                        // 这些方法必须按 method_idx 以升序进行排序。 虚拟方法的 method_idx 不得与任何直接方法相同。
 */

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
    // 类信息索引首地址
    PClassDefsItem m_pClassDefsItem;
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
    // 索引字段信息
    char * indexFieldIds(int index,bool hide = true);
    // 索引方法信息
    char * indexMethodIds(int index,bool hide = true);
    // 索引类信息
public:
    void indexClassDefs(int index,bool hide = true);
};


#endif //READDEX_READDEX_H
