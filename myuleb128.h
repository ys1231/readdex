//
// Created by iyue on 2022/7/14.
//

/**
 * 每个 LEB128 编码值均由 1-5 个字节组成，共同表示一个 32 位的值。
 * 由于是little endian，因此是从低字节到高字节。
 * 每个字节中的最高bit是标识信息，1表示还有后续字节，0表示结束，后面7bits是有效数据。
 * 将多个字节的该7bits从低到高组合起来就是所表示的整数。
 * LEB128分成有符号数和无符号数两种分别进行处理，不过，只是在编码和解码过程有些不同。
 * 这里只关注无符号
 *
 * ULEB128 是一种针对非负整数的可变长度编码，它主要用于需要编码非负整数的地方，比如文件格式和通信协议等。ULEB128 的主要优点是它可以对较小的数字进行紧凑的编码，而对较大的数字则需要更多的字节。
 * 下面，我们来看一个 ULEB128 编码的例子：
 * 假设我们有一个数字 300，我们想要将它转换成 ULEB128 编码。首先，我们将它转换为二进制格式，得到 100101100。
 * 然后，我们将这个二进制数字从右边开始分割成每组7位，如果最左边的一组不足7位，我们用0进行补足，得到 0000100 1011000。
 * 对于每一组，我们都需要加上一个最高位（即第8位），用于表示是否还有更多的字节。如果有更多的字节，我们将最高位设置为1，否则设置为0。这样，我们得到 10000100 01011000，转换为十六进制就是 84 58。
 * 所以，300 的 ULEB128 编码就是 84 58。
 * 在解码的过程中，我们需要按照8位一组的方式来读取字节，并且将每个字节的低7位进行连接，同时，我们需要检查每个字节的最高位，如果最高位为1，那么就表示还有更多的字节，我们需要继续读取，否则表示这是最后一个字节，我们就可以停止读取了。
 */

#ifndef READDEX_MYULEB128_H
#define READDEX_MYULEB128_H

#include <string>
#include <cstdio>
#include <cstdlib>

// 更加优雅的读取
/**
 *
 * @param addr 读取数据的首地址
 * @param value 返回读取的数据
 * @param offset 基于首地址还需要+之前读取的字节数 或者 是返回读取的字节数
 * @return
 */
uint32_t DecodeUleb128(const char* addr, uint32_t &value, uint32_t &offset) {
    const char* ptr = addr + offset;
    int shift = 0;
    uint8_t byte=0;
    value=0;
    do {
        // 在 C++ 中，后缀增加运算符（++）的优先级高于解引用运算符（*）。因此，*ptr++ 等价于 *(ptr++)。
        // 大坑 ptr++ 会导致 下面循环判断条件读取的是下一个字节的数据导致整个解析都会出问题
        byte = *ptr++;
        value |= (byte & 0x7F) << shift;
        shift += 7;
    } while ( byte & 0x80);  // 继续读取，直到遇到最高位为0的字节
    offset = ptr - addr;
    return offset;  // 返回读取的字节数
}

uint32_t decodeULEB128(const char* ptr, uint32_t& result,uint32_t& offset) {

    int bit = 0;
    while (true) {
        char byte = ptr[offset];
        offset += 1;
        result |= (byte & 0x7f) << bit;
        bit += 7;
        if ((byte & 0x80) == 0) {
            break;
        }
    }
    return result;
}


#endif //READDEX_MYULEB128_H
