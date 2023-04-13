# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
#import matplotlib.pyplot as plt
from sklearn import metrics
#from sklearn.svm import SVC
#from sklearn.model_selection import train_test_split
from featurepossess import generate_abnormal
from featurepossess import generate_sql
from featurepossess import generate_xss
from featurepossess import generate_traversal
from featurepossess import generate_crlf
from sklearn.metrics import classification_report
import joblib


'''
如果 flag 的值为 '1'，且 sql_flag 的值为 '0'，则调用 generate 函数生成一个正常测试数据矩阵，并将其保存在 "./data/nor_matrix.csv" 文件中。然后，将该矩阵返回。
如果 flag 的值为 '1'，且 sql_flag 的值为 '1'，则调用 generate 函数生成一个 SQL 注入测试数据矩阵，并将其保存在 "./data/sqltest_matrix.csv" 文件中。然后，将该矩阵返回。
如果 flag 的值不为 '1'，则调用 generate 函数分别生成正常测试数据矩阵和 SQL 注入测试数据矩阵，并将它们保存在 "./data/nortest_matrix.csv" 和 
"./data/sqltest_matrix.csv" 文件中。接着，将这两个矩阵合并成一个完整的测试数据矩阵，并将其保存在 "./data/alltest_matrix.csv" 文件中。最后，返回该文件的路径。
'''

'''
def choose(flag, sql_flag):
    sql_dir = "./data/test/sql/sql_test.csv"
    nor_dir = "./data/test/sql/normal_test.csv"
    allm_dir = "./data/test/sql/all_test_matrix.csv"
    if flag == '1' and sql_flag == '0':
        nor_matrix = generate(nor_dir, "./data/test/sql/nor_test_matrix.csv", 0)
        return nor_matrix
    elif flag == '1' and sql_flag == '1':
        sql_matrix = generate(sql_dir, "./data/test/sql/sql_test_matrix.csv", 1)
        return sql_matrix
    else:
        sql_matrix = generate(sql_dir, "./data/test/sql/sql_test_matrix.csv", 1)
        nor_matrix = generate(nor_dir, "./data/test/sql/nor_test_matrix.csv", 0)
        df = pd.read_csv(sql_matrix)
        df.to_csv(allm_dir, encoding="utf_8_sig", index=False)
        df = pd.read_csv(nor_matrix)
        df.to_csv(allm_dir, encoding="utf_8_sig", index=False, header=False, mode='a+')
        return allm_dir
'''

normal_dir = "./data/test/normal/normal_test.csv"
sql_dir = "./data/test/sql/sql_test.csv"
xss_dir = "./data/test/xss/xss_test.csv"
traversal_dir = "./data/test/traversal/traversal_test.csv"
crlf_dir = "./data/test/crlf/crlf_test.csv"


# 函数从该文件中读取测试数据，并将其分成特征矩阵和目标向量两部分
def gen_data(allm_dir):
    feature_max = pd.read_csv(allm_dir)
    arr = feature_max.values
    data = np.delete(arr, -1, axis=1)  # 删除最后一列
    # print(arr)
    test_target = arr[:, 7]
    return data, test_target


def gen_data_crlf(allm_dir):
    feature_max = pd.read_csv(allm_dir)
    arr = feature_max.values
    data = np.delete(arr, -1, axis=1)  # 删除最后一列
    # print(arr)
    test_target = arr[:, 3]
    return data, test_target


def gen_data_xss(allm_dir):
    feature_max = pd.read_csv(allm_dir)
    arr = feature_max.values
    data = np.delete(arr, -1, axis=1)  # 删除最后一列
    # print(arr)
    test_target = arr[:, 3]
    return data, test_target


def gen_data_normal(allm_dir):
    feature_max = pd.read_csv(allm_dir)
    arr = feature_max.values
    data = np.delete(arr, -1, axis=1)  # 删除最后一列
    # print(arr)
    test_target = arr[:, 13]
    return data, test_target


def Normal(model):
    normal_test_matrix = generate_abnormal(normal_dir, "./data/test/normal/normal_test_matrix.csv", 1)
    if model == 1:
        clf = joblib.load("./model/knn_normal.model")
        print("KNN Normal Model has been loaded")
    else:
        clf = joblib.load("./model/logistic_normal.model")
        print("Logistic Normal Model has been loaded")
    return normal_test_matrix, clf


def Sql(model):
    sql_test_matrix = generate_sql(sql_dir, "./data/test/sql/sql_test_matrix.csv", 1)
    if model == 1:
        clf = joblib.load("./model/knn_sql.model")
        print("KNN SQL Model has been loaded")
    else:
        clf = joblib.load("./model/logistic_sql.model")
        print("Logistic SQL Model has been loaded")
    return sql_test_matrix, clf


def Xss(model):
    xss_test_matrix = generate_xss(xss_dir, "./data/test/xss/xss_test_matrix.csv", 1)
    if model == 1:
        clf = joblib.load("./model/knn_xss.model")
        print("KNN XSS Model has been loaded")
    else:
        clf = joblib.load("./model/logistic_xss.model")
        print("Logistic XSS Model has been loaded")
    return xss_test_matrix, clf


def Traversal(model):
    traversal_test_matrix = generate_traversal(traversal_dir, "./data/test/traversal/traversal_test_matrix.csv", 1)
    if model == 1:
        clf = joblib.load("./model/knn_traversal.model")
        print("KNN Traversal Model has been loaded")
    else:
        clf = joblib.load("./model/logistic_traversal.model")
        print("Logistic Traversal Model has been loaded")
    return traversal_test_matrix, clf


def Crlf(model):
    crlf_test_matrix = generate_crlf(crlf_dir, "./data/test/crlf/crlf_test_matrix.csv", 1)
    if model == 1:
        clf = joblib.load("./model/knn_crlf.model")
        print("KNN CRLF Model has been loaded")
    else:
        clf = joblib.load("./model/logistic_crlf.model")
        print("Logistic CRLF Model has been loaded")
    return crlf_test_matrix, clf


def choose_model():
    print("*" * 42)
    print("请输入要进行哪种模块的测试")
    print("1.knn    2.logistic    3.quit")
    print("*" * 42)
    Model = input()
    if int(Model) == 1:
        res = 1
    elif int(Model) == 2:
        res = 2
    elif int(Model) == 3:
        res = 3
    else:
        print("Invalid Input")
        res = 0
    return res


# 字典
switch = {
    1: Normal,
    2: Sql,
    3: Xss,
    4: Traversal,
    5: Crlf
}


def test():
    while (1):
        f = choose_model()
        if f == 3:
            break
        while f == 0:
            f = choose_model()
        print("*" * 42)
        print("请输入要进行哪种攻击的检测")
        print("1.正常流量       2.sql注入攻击       3.xss攻击")
        print("4.目录遍历攻击    5.crlf注入攻击      6.退出")
        print("*" * 42)
        flag = input()
        if int(flag) == 6:
            break
        if int(flag) < 1 or int(flag) > 6:
            print("Invalid Input")
            continue
        mode, clf = switch.get(int(flag))(f)
        if int(flag) == 5:
            test_data, test_target = gen_data_crlf(mode)
        elif int(flag) == 1:
            test_data, test_target = gen_data_normal(mode)
        elif int(flag) == 3:
            test_data, test_target = gen_data_xss(mode)
        else:
            test_data, test_target = gen_data(mode)
        y_pred = clf.predict(test_data)
        # print("y_pred:%s" % y_pred)
        # print("test_target:%s" % test_target)
        # Verify
        # report = classification_report(test_target, y_pred, zero_division=1)
        # print(report)
        print("*" * 42)
        print("本次测试共有%d条数据用于测试" % len(y_pred))
        print('准确度为:{:.1%}'.format(metrics.precision_score(y_true=test_target, y_pred=y_pred)))  # 准确率
        print('召回率为:{:.1%}'.format(metrics.recall_score(y_true=test_target, y_pred=y_pred)))  # 召回率
        print('F1的值为:{:.1%}'.format(metrics.f1_score(y_true=test_target, y_pred=y_pred)))  # F1的值
        print("混淆矩阵如下所示:")
        print(metrics.confusion_matrix(y_true=test_target, y_pred=y_pred))  # 混淆矩阵
        print("*" * 42)

