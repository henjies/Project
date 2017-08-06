#coding=utf-8

# @brief   : 用来解密金山安全卫士，安全狗两个产品的漏洞库文件，
#   得到xml格式的补丁信息
# @author  : hsj
# @version : 1.0

import os
from xml.sax.saxutils import unescape

import sys
reload( sys )
sys.setdefaultencoding('utf-8')


class LocalError(Exception):
    pass

def _get_key_data(file_name):
    """
    获取加密密钥和文件内容
    前80字节为文件头部，里面包括加密方式和加密密钥，第49个字节为加密密钥
    文件偏移80字节后就是库文件加密的内容
    :param file_name: 库文件名称，和main函数同一级目录
    :return: 密钥，库文件内容
    """
    if not file_name:
        raise LocalError('输入库文件名字为空，请输入补丁库文件名称！！！')
    if not os.path.isfile(file_name):
        current_path = os.getcwd()
        raise LocalError('当前路径：%s下不存在文件：%s' % (current_path,
                                               file_name))
    with open(file_name, 'rb') as file_handle:
        file_handle.seek(0)
        file_handle.seek(48)
        decode_key = file_handle.read(1)
        file_handle.seek(80, 0)
        content_data = file_handle.read()
    return decode_key, content_data


def _decode_content(decode_key, file_content):
    """
    根据密钥解密文件内容
    加解密方法都是文件内容的每个字节和密钥进行异或
    """
    return ''.join([chr(ord(i)^ord(decode_key)) for i in file_content])


def _save_file(file_content):
    """保存解密后文件到脚本运行路径下"""
    with open('result.xml', 'w') as file_handle:
        #file_content.decode('gb2312').encode('utf-8')
        #file_content.replace('gb2312', 'utf-8')
        file_handle.write(unescape(file_content).replace("&quot", ''))

    
def main():
    """主函数"""
    file_path = 'system64.dat'
    decode_key, file_content = _get_key_data(file_path)
    ret_val = _decode_content(decode_key, file_content)
    _save_file(ret_val)
    print '数据解析成功'

if __name__ == '__main__':
    try:
        main()
    except LocalError as ex:
        print str(ex)
    except Exception as ex:
        print str(ex)
