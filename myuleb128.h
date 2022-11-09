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
 */

#ifndef READDEX_MYULEB128_H
#define READDEX_MYULEB128_H

#include <string>
#include <cstdio>
#include <cstdlib>

typedef unsigned char uchar;

/**
 *
 * @param addr 解析的首地址
 * @param size  返回可变类型值
 * @param moveBit  返回所占字节数 方便索引下一个数据使用
 * @param _moveBit 当前可变数据的起始偏移地址 默认为0
 * @return  执行成功或失败
 */
bool myDecodeUleb128(uchar *addr , int *size, unsigned char &moveBit, int _moveBit = 0) {
    // uchar * _size = (uchar * )(size);
    uchar *ptr = (addr + _moveBit);
    uchar tmp2 = 0;
    // 检测是否有下一个字节
    if (((*ptr) & 0x80) == 0) {
        *size = (*ptr) & 0x7F; // 0111 1111
        moveBit += 1;
        return true;
    }

    *size = (*ptr) & 0x7F;
    // 获取到完整的第一个字节 拼接到第8位
    tmp2 = (*(ptr + 1)) & 0x1; // 0000 0001
    *size |= tmp2 << (7); // 1000 0000
    moveBit += 1;
    // 1111 1111
    // 已经拿到完整的一个字节

    // 获取第二个字节
    if (((*(ptr + 1)) & 0x80) == 0) {
        tmp2 = (*(ptr + 1)) & 0x7E; // 0111 1110
        *size |= tmp2 << (-1 + 8);  // 0001 1111 1000 0000
        moveBit += 1;
        return true;
    }
    // 第二个字节为第一位1 需要继续获取下一个
    // 最高位置0 拿到中间6位
    tmp2 = (*(ptr + 1)) & 0x7E;// 0111 1110
    *size |= tmp2 << (-1 + 8); // 0011 1110 0000 0000
    // 获取到完整的第二个字节 拼接到第14位
    tmp2 = (*(ptr + 2)) & 0x3; // 0000 0011
    *size |= tmp2 << (-2 + 16); // 1100 0000 0000 0000
    moveBit += 1;
    //                 1111 1111 1111 1111

    // 获取第三个字节 末尾2位已使用
    if (((*(ptr + 2)) & 0x80) == 0) {
        // 直接赋值为0 并获取  0111 1100   A10 B11 C12 D 13 E14 F15
        *size |= ((*ptr + 2) & 0x7C) << (-2 + 24);
        moveBit += 1;
        return true; // 直接赋值为0 并获取第一个字节值
    }
    *size |= ((*ptr + 2) & 0x7C) << (-2 + 24); //  0001 1111
    // 获取到完整的第三个字节
    tmp2 = (*(ptr + 3)) & 0x7;// 0000 0111
    *size |= tmp2 << (-3 + 24);// 1110 0000
    moveBit += 1;

    // 获取第四个字节 末尾3位已使用
    if (((*(ptr + 3)) & 0x80) == 0) {
        // 0111 1000 78
        *size |= ((*ptr + 3) & 0x78) << (-3 + 32); // 0000 1111
        moveBit += 1;
        return true; // 直接赋值为0 并获取第一个字节值
    }
    // 第二个字节为第一位1 需要继续获取下一个
    *size |= ((*ptr + 3) & 0x78) << (-3 + 32); //
    // 获取到完整的第四个字节
    tmp2 = (*(ptr + 4)) & 0xF;// 0000 1111
    *size |= tmp2 << (-4 + 24);// 0000 0000 1111
    moveBit += 1;

    if (((*(ptr + 4)) & 0x80) != 0)
        return false;
    else
        return true;
}


#endif //READDEX_MYULEB128_H
