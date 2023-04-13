# -*- coding: UTF-8 -*-
import re

SpecialChars = ['\'', '\"', '!', '%', '#', '&', ':', ';', '<', '>', '='
    , '?', '@', ']', '[', '(', ')', '{', '}', '$', '*', '+'
    , '-']


def generate_url_sql(url):  # url:传入的url
    num_len = 0  # 数字的数量
    capital_len = 0  # 大写字母的数量
    key_num = 0
    capital_f = 0
    num_f = 0
    space_f = 0
    special_f = 0
    prefix_f = 0
    num_len = len(re.compile(r'\d').findall(url))
    if len(url) != 0:
        num_f = num_len / len(url)  # 数字字符频率
    capital_len = len(re.compile(r'[A-Z]').findall(url))
    if len(url) != 0:
        capital_f = capital_len / len(url)  # 大写字母频率
    url = url.lower()  # 全部变为小写字母

    key_num = key_num + url.count('and')
    key_num = key_num + url.count('or')
    key_num = key_num + url.count('xor')
    key_num = key_num + url.count('version')
    key_num = key_num + url.count('substr')
    key_num = key_num + url.count('substring')
    key_num = key_num + url.count('len')
    key_num = key_num + url.count('length')
    key_num = key_num + url.count('benchmark')
    key_num = key_num + url.count('shutdown')
    key_num = key_num + url.count('mid')
    key_num = key_num + url.count('aes')
    key_num = key_num + url.count('xp_cmdshell')
    key_num = key_num + url.count('exec')
    key_num = key_num + url.count('union')
    key_num = key_num + url.count('order')
    key_num = key_num + url.count('information schema')
    key_num = key_num + url.count('sleep')
    key_num = key_num + url.count('md5')
    key_num = key_num + url.count('database')
    key_num = key_num + url.count('load_file')
    key_num = key_num + url.count('load data infile')
    key_num = key_num + url.count('into outfile')
    key_num = key_num + url.count('into dumpfile')

    if len(url) != 0:
        space_f = (url.count(" ") + url.count("%20")) / len(url)  # 空格百分比
        prefix_f = (url.count('\\x') + url.count('\\u')) / len(url)  # 前缀百分比
        count = 0  # 特殊字符的数量
        for char in url:
            if char in SpecialChars:
                count += 1
        special_f = count / len(url)  # 特殊字符百分比
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
    feature = [len(url), key_num, capital_f, num_f, space_f, special_f, prefix_f]

    return feature                  # 将提取的特征值以列表的形式返回


def generate_url_xss(url):
    num_len = 0  # 数字的数量
    capital_len = 0  # 大写字母的数量
    key_num = 0
    capital_f = 0
    num_f = 0
    space_f = 0
    special_f = 0
    prefix_f = 0
    num_len = len(re.compile(r'\d').findall(url))
    if len(url) != 0:
        num_f = num_len / len(url)  # 数字字符频率
    capital_len = len(re.compile(r'[A-Z]').findall(url))
    if len(url) != 0:
        capital_f = capital_len / len(url)  # 大写字母频率
    url = url.lower()  # 全部变为小写字母

    key_num = key_num + url.count('script')
    key_num = key_num + url.count('alert')
    key_num = key_num + url.count('src')
    key_num = key_num + url.count('href')
    key_num = key_num + url.count('@import')
    key_num = key_num + url.count('eval')
    key_num = key_num + url.count('document')
    key_num = key_num + url.count('eval')
    key_num = key_num + url.count('javascript')
    key_num = key_num + url.count('iframe')
    key_num = key_num + url.count('onerror')
    key_num = key_num + url.count('sleep')
    key_num = key_num + url.count('document')

    if len(url) != 0:
        space_f = (url.count(" ") + url.count("%20")) / len(url)  # 空格百分比
        prefix_f = (url.count('\\x') + url.count('\\u')) / len(url)  # 前缀百分比
        count = 0  # 特殊字符的数量
        for char in url:
            if char in SpecialChars:
                count += 1
        special_f = count / len(url)  # 特殊字符百分比

    feature = [key_num, capital_f, prefix_f]

    '''
    特征值依次为：
        字符个数
        xss攻击关键词数量
        大写字符百分比
        数字字符百分比
        空格百分比
        特殊字符百分比
        前缀百分比
    '''

    return feature


def generate_url_traversal(url):
    url = url.lower()  # 全部变为小写字母
    len1 = 0  # ..的数量
    len2 = 0  # //的数量
    len3 = 0  # ../的数量
    len4 = 0  # 特殊字符的数量
    len5 = 0  # /.的数量
    key_num = 0
    special_f = 0
    len1 = url.count('..')  # 统计..出现的次数
    len2 = url.count('//')  # 统计//出现的次数
    len3 = url.count('/')  # 统计/出现的次数
    len5 = url.count('.')  # 统计.出现的次数
    if len(url) != 0:
        for char in url:
            if char in SpecialChars:
                len4 += 1
        special_f = len4 / len(url)  # 特殊字符百分比

    key_num = key_num + url.count('etc')
    key_num = key_num + url.count('passwd')
    key_num = key_num + url.count('system32')

    feature = [key_num, len1, len2, len3, len4, len5, special_f]
    '''
    特征值依次为：
        关键词出现次数
        ..出现次数
        //出现次数
        /出现次数
        .出现次数
        特殊字符出现次数
        特殊字符百分比
    '''
    return feature


def generate_url_crlf(url):
    url = url.lower()  # 全部变为小写字母
    len1 = url.count("%a")  # %a出现的次数
    len2 = url.count("%d")  # %d出现的次数
    len3 = url.count("%a%d")  # %a%d出现的次数

    feature = [len1, len2, len3]
    '''
    特征值依次为：
        %a出现的次数
        %d出现的次数
        %a%d出现的次数
    '''
    return feature


def generate_url_abnormal(url):
    num_len = 0  # 数字的数量
    capital_len = 0  # 大写字母的数量
    key_num = 0
    capital_f = 0
    num_f = 0
    space_f = 0
    special_f = 0
    prefix_f = 0
    num_len = len(re.compile(r'\d').findall(url))
    len1 = url.count('..')  # 统计..出现的次数
    len2 = url.count('//')  # 统计//出现的次数
    len3 = url.count('/')  # 统计/出现的次数
    len4 = url.count('.')  # 统计.出现的次数
    len5 = url.count("%a")  # %a出现的次数
    len6 = url.count("%d")  # %d出现的次数
    len7 = url.count("%a%d")  # %a%d出现的次数
    if len(url) != 0:
        num_f = num_len / len(url)  # 数字字符频率
    capital_len = len(re.compile(r'[A-Z]').findall(url))
    if len(url) != 0:
        capital_f = capital_len / len(url)  # 大写字母频率
    url = url.lower()  # 全部变为小写字母

    key_num = key_num + url.count('and')
    key_num = key_num + url.count('or')
    key_num = key_num + url.count('xor')
    key_num = key_num + url.count('version')
    key_num = key_num + url.count('substr')
    key_num = key_num + url.count('substring')
    key_num = key_num + url.count('len')
    key_num = key_num + url.count('length')
    key_num = key_num + url.count('benchmark')
    key_num = key_num + url.count('shutdown')
    key_num = key_num + url.count('mid')
    key_num = key_num + url.count('aes')
    key_num = key_num + url.count('xp_cmdshell')
    key_num = key_num + url.count('exec')
    key_num = key_num + url.count('union')
    key_num = key_num + url.count('order')
    key_num = key_num + url.count('information schema')
    key_num = key_num + url.count('sleep')
    key_num = key_num + url.count('md5')
    key_num = key_num + url.count('database')
    key_num = key_num + url.count('load_file')
    key_num = key_num + url.count('load data infile')
    key_num = key_num + url.count('into outfile')
    key_num = key_num + url.count('into dumpfile')
    key_num = key_num + url.count('script')
    key_num = key_num + url.count('alert')
    key_num = key_num + url.count('src')
    key_num = key_num + url.count('href')
    key_num = key_num + url.count('@import')
    key_num = key_num + url.count('eval')
    key_num = key_num + url.count('document')
    key_num = key_num + url.count('eval')
    key_num = key_num + url.count('javascript')
    key_num = key_num + url.count('iframe')
    key_num = key_num + url.count('onerror')
    key_num = key_num + url.count('sleep')
    key_num = key_num + url.count('document')
    key_num = key_num + url.count('etc')
    key_num = key_num + url.count('passwd')
    key_num = key_num + url.count('system32')

    if len(url) != 0:
        space_f = (url.count(" ") + url.count("%20")) / len(url)  # 空格百分比
        prefix_f = (url.count('\\x') + url.count('\\u')) / len(url)  # 前缀百分比
        count = 0  # 特殊字符的数量
        for char in url:
            if char in SpecialChars:
                count += 1
        special_f = count / len(url)  # 特殊字符百分比

    feature = [len1, len2, len3, len4, len5, len6, len7, key_num, capital_f, num_f, space_f, special_f, prefix_f]
    # 特征值为全部异常流量的特征值
    return feature
