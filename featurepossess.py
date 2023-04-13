# -*- coding: UTF-8 -*-
import re

SpecialChars = ['\'', '\"', '!', '%', '#', '&', ':', ';', '<', '>', '='
    , '?', '@', ']', '[', '(', ')', '{', '}', '$', '*', '+'
    , '-']


def generate_sql(odir, wdir, label):  # odir:要打开的数据集的路径    wdir:生成特征向量的文件路径    lable:标志打开的是正常数据(0)还是恶意流量(1)
    f_input = open(wdir, 'w')  # 打开生成特征向量数据文件，并将文件对象赋值给变量f_input
    with open(odir, 'rb') as f:  # 打开原始数据文件，并将其中的文本数据逐行读取到一个列表变量data中
        data = [x.decode('utf-8').strip() for x in f.readlines()]  # strip()作用:将收尾的空格去除
        # print(data)
        line_number = 0

        for line in data:  # 将每一行的数据读取到变量line中
            # global feature
            num_len = 0  # 数字的数量
            capital_len = 0  # 大写字母的数量
            key_num = 0
            # feature3 = 0
            line_number = line_number + 1
            num_len = len(re.compile(r'\d').findall(line))
            if len(line) != 0:
                num_f = num_len / len(line)  # 数字字符频率
            capital_len = len(re.compile(r'[A-Z]').findall(line))
            if len(line) != 0:
                capital_f = capital_len / len(line)  # 大写字母频率
            line = line.lower()  # 全部变为小写字母

            key_num = key_num + line.count('and')
            key_num = key_num + line.count('or')
            key_num = key_num + line.count('xor')
            key_num = key_num + line.count('version')
            key_num = key_num + line.count('substr')
            key_num = key_num + line.count('substring')
            key_num = key_num + line.count('len')
            key_num = key_num + line.count('length')
            key_num = key_num + line.count('benchmark')
            key_num = key_num + line.count('shutdown')
            key_num = key_num + line.count('mid')
            key_num = key_num + line.count('aes')
            key_num = key_num + line.count('xp_cmdshell')
            key_num = key_num + line.count('exec')
            key_num = key_num + line.count('union')
            key_num = key_num + line.count('order')
            key_num = key_num + line.count('information schema')
            key_num = key_num + line.count('sleep')
            key_num = key_num + line.count('md5')
            key_num = key_num + line.count('database')
            key_num = key_num + line.count('load_file')
            key_num = key_num + line.count('load data infile')
            key_num = key_num + line.count('into outfile')
            key_num = key_num + line.count('into dumpfile')

            # key_num=key_num+line.count('load_file%20')+line.count('load data infile%20')+line.count('into outfile%20')+line.count('into dumpfile%20')
            if len(line) != 0:
                space_f = (line.count(" ") + line.count("%20")) / len(line)  # 空格百分比
                prefix_f = (line.count('\\x') + line.count('\\u')) / len(line)  # 前缀百分比
                count = 0  # 特殊字符的数量
                for char in line:
                    if char in SpecialChars:
                        count += 1
                special_f = count / len(line)  # 特殊字符百分比
            # print('%f,%f,%f,%f,%f,%f,%f,%f' % (len(line),key_num,capital_f,num_f,space_f,special_f,prefix_f,label))

            f_input.write('%f,%f,%f,%f,%f,%f,%f,%f' % (
                len(line), key_num, capital_f, num_f, space_f, special_f, prefix_f,
                label) + '\n')  # 将特征向量写入特征向量文件中，每个分量用，分隔
            '''
            特征值依次为：
            字符个数
            sql注入关键词数量
            大写字符百分比
            数字字符百分比
            空格百分比
            特殊字符百分比
            前缀百分比
            '''
    f_input.close()
    return wdir


def generate_xss(odir, wdir, label):
    f_input = open(wdir, 'w')  # 打开生成特征向量数据文件，并将文件对象赋值给变量f_input
    with open(odir, 'rb') as f:  # 打开原始数据文件，并将其中的文本数据逐行读取到一个列表变量data中
        data = [x.decode('utf-8').strip() for x in f.readlines()]  # strip()作用:将收尾的空格去除
        # print(data)
        line_number = 0

        for line in data:  # 将每一行的数据读取到变量line中
            num_len = 0  # 数字的数量
            capital_len = 0  # 大写字母的数量
            key_num = 0
            line_number = line_number + 1
            num_len = len(re.compile(r'\d').findall(line))
            if len(line) != 0:
                num_f = num_len / len(line)  # 数字字符频率
            capital_len = len(re.compile(r'[A-Z]').findall(line))
            if len(line) != 0:
                capital_f = capital_len / len(line)  # 大写字母频率
            line = line.lower()  # 全部变为小写字母

            key_num = key_num + line.count('script')
            key_num = key_num + line.count('alert')
            key_num = key_num + line.count('src')
            key_num = key_num + line.count('href')
            key_num = key_num + line.count('@import')
            key_num = key_num + line.count('eval')
            key_num = key_num + line.count('document')
            key_num = key_num + line.count('eval')
            key_num = key_num + line.count('javascript')
            key_num = key_num + line.count('iframe')
            key_num = key_num + line.count('onerror')
            key_num = key_num + line.count('sleep')
            key_num = key_num + line.count('document')

            if len(line) != 0:
                space_f = (line.count(" ") + line.count("%20")) / len(line)  # 空格百分比
                prefix_f = (line.count('\\x') + line.count('\\u')) / len(line)  # 前缀百分比
                count = 0  # 特殊字符的数量
                for char in line:
                    if char in SpecialChars:
                        count += 1
                special_f = count / len(line)  # 特殊字符百分比
            # print('%f,%f,%f,%f,%f,%f,%f,%f' % (len(line),key_num,capital_f,num_f,space_f,special_f,prefix_f,label))

            f_input.write('%f,%f,%f,%f' % (
                key_num, capital_f, prefix_f,
                label) + '\n')  # 将特征向量写入特征向量文件中，每个分量用，分隔
            '''
            特征值依次为：
            xss攻击关键词数量
            大写字符百分比
            前缀百分比
            '''
    f_input.close()
    return wdir


def generate_traversal(odir, wdir, label):
    f_input = open(wdir, 'w')  # 打开生成特征向量数据文件，并将文件对象赋值给变量f_input
    with open(odir, 'rb') as f:  # 打开原始数据文件，并将其中的文本数据逐行读取到一个列表变量data中
        data = [x.decode('utf-8').strip() for x in f.readlines()]  # strip()作用:将收尾的空格去除
        # print(data)
        line_number = 0

        for line in data:  # 将每一行的数据读取到变量line中
            line = line.lower()  # 全部变为小写字母
            len1 = 0  # ..的数量
            len2 = 0  # //的数量
            len3 = 0  # ../的数量
            len4 = 0  # 特殊字符的数量
            len5 = 0  # /.的数量
            key_num = 0
            line_number = line_number + 1
            len1 = line.count('..')  # 统计..出现的次数
            len2 = line.count('//')  # 统计//出现的次数
            len3 = line.count('/')  # 统计/出现的次数
            len5 = line.count('.')  # 统计.出现的次数
            if len(line) != 0:
                for char in line:
                    if char in SpecialChars:
                        len4 += 1
                special_f = len4 / len(line)  # 特殊字符百分比

            key_num = key_num + line.count('etc')
            key_num = key_num + line.count('passwd')
            key_num = key_num + line.count('system32')

            f_input.write('%f,%f,%f,%f,%f,%f,%f,%f' % (
                key_num, len1, len2, len3, len4, len5, special_f,
                label) + '\n')  # 将特征向量写入特征向量文件中，每个分量用，分隔
            '''
            特征值依次为：
            关键词出现次数
            ..出现次数
            //出现次数
            ../出现次数
            /.出现次数
            特殊字符出现次数
            特殊字符百分比
            '''
    f_input.close()
    return wdir


def generate_crlf(odir, wdir, label):
    f_input = open(wdir, 'w')  # 打开生成特征向量数据文件，并将文件对象赋值给变量f_input
    with open(odir, 'rb') as f:  # 打开原始数据文件，并将其中的文本数据逐行读取到一个列表变量data中
        data = [x.decode('utf-8').strip() for x in f.readlines()]  # strip()作用:将收尾的空格去除
        line_number = 0

        for line in data:  # 将每一行的数据读取到变量line中
            line = line.lower()  # 全部变为小写字母
            line_number = line_number + 1
            len1 = line.count("%a")     # %a出现的次数
            len2 = line.count("%d")     # %d出现的次数
            len3 = line.count("%a%d")   # %a%d出现的次数

            f_input.write('%f,%f,%f,%f' % (
                len1, len2, len3,
                label) + '\n')  # 将特征向量写入特征向量文件中，每个分量用，分隔
            '''
            特征值依次为：
            %a出现的次数
            %d出现的次数
            %a%d出现的次数
            '''
    f_input.close()
    return wdir


def generate_abnormal(odir, wdir, label=1):  # odir:要打开的数据集的路径    wdir:生成特征向量的文件路径    lable:标志打开的是正常数据(0)还是恶意流量(1)
    f_input = open(wdir, 'w')  # 打开生成特征向量数据文件，并将文件对象赋值给变量f_input
    with open(odir, 'rb') as f:  # 打开原始数据文件，并将其中的文本数据逐行读取到一个列表变量data中
        data = [x.decode('utf-8').strip() for x in f.readlines()]  # strip()作用:将收尾的空格去除
        line_number = 0

        for line in data:  # 将每一行的数据读取到变量line中
            num_len = 0  # 数字的数量
            capital_len = 0  # 大写字母的数量
            key_num = 0
            line_number = line_number + 1
            num_len = len(re.compile(r'\d').findall(line))
            len1 = line.count('..')  # 统计..出现的次数
            len2 = line.count('//')  # 统计//出现的次数
            len3 = line.count('/')  # 统计/出现的次数
            len4 = line.count('.')  # 统计.出现的次数
            len5 = line.count("%a")  # %a出现的次数
            len6 = line.count("%d")  # %d出现的次数
            len7 = line.count("%a%d")  # %a%d出现的次数
            if len(line) != 0:
                num_f = num_len / len(line)  # 数字字符频率
            capital_len = len(re.compile(r'[A-Z]').findall(line))
            if len(line) != 0:
                capital_f = capital_len / len(line)  # 大写字母频率
            line = line.lower()  # 全部变为小写字母

            key_num = key_num + line.count('and')
            key_num = key_num + line.count('or')
            key_num = key_num + line.count('xor')
            key_num = key_num + line.count('version')
            key_num = key_num + line.count('substr')
            key_num = key_num + line.count('substring')
            key_num = key_num + line.count('len')
            key_num = key_num + line.count('length')
            key_num = key_num + line.count('benchmark')
            key_num = key_num + line.count('shutdown')
            key_num = key_num + line.count('mid')
            key_num = key_num + line.count('aes')
            key_num = key_num + line.count('xp_cmdshell')
            key_num = key_num + line.count('exec')
            key_num = key_num + line.count('union')
            key_num = key_num + line.count('order')
            key_num = key_num + line.count('information schema')
            key_num = key_num + line.count('sleep')
            key_num = key_num + line.count('md5')
            key_num = key_num + line.count('database')
            key_num = key_num + line.count('load_file')
            key_num = key_num + line.count('load data infile')
            key_num = key_num + line.count('into outfile')
            key_num = key_num + line.count('into dumpfile')
            key_num = key_num + line.count('script')
            key_num = key_num + line.count('alert')
            key_num = key_num + line.count('src')
            key_num = key_num + line.count('href')
            key_num = key_num + line.count('@import')
            key_num = key_num + line.count('eval')
            key_num = key_num + line.count('document')
            key_num = key_num + line.count('eval')
            key_num = key_num + line.count('javascript')
            key_num = key_num + line.count('iframe')
            key_num = key_num + line.count('onerror')
            key_num = key_num + line.count('sleep')
            key_num = key_num + line.count('document')
            key_num = key_num + line.count('etc')
            key_num = key_num + line.count('passwd')
            key_num = key_num + line.count('system32')

            if len(line) != 0:
                space_f = (line.count(" ") + line.count("%20")) / len(line)  # 空格百分比
                prefix_f = (line.count('\\x') + line.count('\\u')) / len(line)  # 前缀百分比
                count = 0  # 特殊字符的数量
                for char in line:
                    if char in SpecialChars:
                        count += 1
                special_f = count / len(line)  # 特殊字符百分比

            f_input.write('%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f' % (
                len1, len2, len3, len4, len5, len6, len7,
                key_num, capital_f, num_f, space_f, special_f, prefix_f,
                label) + '\n')                 # 将特征向量写入特征向量文件中，每个分量用，分隔
            # 特征值为全部异常流量的特征值
    f_input.close()
    return wdir
