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
from feature_extract_url import generate_url_abnormal
from feature_extract_url import generate_url_sql
from feature_extract_url import generate_url_xss
from feature_extract_url import generate_url_traversal
from feature_extract_url import generate_url_crlf
import joblib
import csv

# knn算法模型路径
knn_normal_model_dir = "./model/knn_normal.model"
knn_sql_model_dir = "./model/knn_sql.model"
knn_xss_model_dir = "./model/knn_xss.model"
knn_traversal_model_dir = "./model/knn_traversal.model"
knn_crlf_model_dir = "./model/knn_crlf.model"
# 逻辑回归算法模型路径
logistic_normal_model_dir = "./model/logistic_normal.model"
logistic_sql_model_dir = "./model/logistic_sql.model"
logistic_xss_model_dir = "./model/logistic_xss.model"
logistic_traversal_model_dir = "./model/logistic_traversal.model"
logistic_crlf_model_dir = "./model/logistic_crlf.model"

my_map = {-1: "其他种类恶意流量", 0: "正常流量", 1: "SQL注入攻击", 2: "xss攻击", 3: "目录遍历攻击", 4: "crlf注入攻击"}
my_map_knn_dir = {0: "./data/knn/normal/normal_train.csv", 1: "./data/knn/sql/sql_train.csv", 2: "./data/knn/xss/xss_train.csv",
                  3: "./data/knn/traversal/traversal_train.csv", 4: "./data/knn/crlf/crlf_train.csv"}

my_map_logistic_dir = {0: "./data/logistic/normal/normal_train.csv", 1: "./data/logistic/sql/sql_train.csv",
                       2: "./data/logistic/xss/xss_train.csv", 3: "./data/logistic/traversal/traversal_train.csv",
                       4: "./data/logistic/crlf/crlf_train.csv"}


def url_logistic_test(url):
    # logistic模型检测正常流量
    feature_logistic_normal = generate_url_abnormal(url)
    arr_logistic_normal = [feature_logistic_normal]
    clf_logistic_normal = joblib.load("./model/logistic_normal.model")
    pred_logistic_normal = clf_logistic_normal.predict(arr_logistic_normal)
    pred_logistic_normal = int(pred_logistic_normal[0])

    # logistic模型检测sql注入流量
    feature_logistic_sql = generate_url_sql(url)
    arr_logistic_sql = [feature_logistic_sql]
    clf_logistic_sql = joblib.load("./model/logistic_sql.model")
    pred_logistic_sql = clf_logistic_sql.predict(arr_logistic_sql)
    pred_logistic_sql = int(pred_logistic_sql[0])

    # logistic模型检测xss攻击流量
    feature_logistic_xss = generate_url_xss(url)
    arr_logistic_xss = [feature_logistic_xss]
    clf_logistic_xss = joblib.load("./model/logistic_xss.model")
    pred_logistic_xss = clf_logistic_xss.predict(arr_logistic_xss)
    pred_logistic_xss = int(pred_logistic_xss[0])

    # logistic模型检测traversal攻击流量
    feature_logistic_traversal = generate_url_traversal(url)
    arr_logistic_traversal = [feature_logistic_traversal]
    clf_logistic_traversal = joblib.load("./model/logistic_traversal.model")
    pred_logistic_traversal = clf_logistic_traversal.predict(arr_logistic_traversal)
    pred_logistic_traversal = int(pred_logistic_traversal[0])

    # logistic模型检测crlf注入流量
    feature_logistic_crlf = generate_url_crlf(url)
    arr_logistic_crlf = [feature_logistic_crlf]
    clf_logistic_crlf = joblib.load("./model/logistic_crlf.model")
    pred_logistic_crlf = clf_logistic_crlf.predict(arr_logistic_crlf)
    pred_logistic_crlf = int(pred_logistic_crlf[0])

    res = [pred_logistic_normal, pred_logistic_sql, pred_logistic_xss, pred_logistic_traversal, pred_logistic_crlf]
    print("*" * 42)
    print("以下是逻辑回归模型进行的预测报告")
    print("以下报告中1代表真，0代表假")
    print("预测为正常流量: %d" % pred_logistic_normal)
    print("预测为sql注入攻击: %d" % pred_logistic_sql)
    print("预测为xss攻击: %d" % pred_logistic_xss)
    print("预测为目录遍历攻击: %d" % pred_logistic_traversal)
    print("预测为crlf注入攻击: %d" % pred_logistic_crlf)
    no = -1
    if res.count(1) != 1:           # 正例的数量大于1则认为是其他种类恶意流量
        print("系统判断该流量不属于上述五种中的任何一种，怀疑可能是其他种类恶意流量")
    else:
        no = res.index(1)           # 找到唯一一个正例的序号
        print("逻辑回归模型预测该流量属于%s" % my_map[no])
    print("*" * 42)
    return no


def url_knn_test(url):
    # knn模型检测正常流量
    feature_knn_normal = generate_url_abnormal(url)
    arr_knn_normal = [feature_knn_normal]
    clf_knn_normal = joblib.load("./model/knn_normal.model")
    pred_knn_normal = clf_knn_normal.predict(arr_knn_normal)
    pred_knn_normal = int(pred_knn_normal[0])

    # knn模型检测sql注入流量
    feature_knn_sql = generate_url_sql(url)
    arr_knn_sql = [feature_knn_sql]
    clf_knn_sql = joblib.load("./model/knn_sql.model")
    pred_knn_sql = clf_knn_sql.predict(arr_knn_sql)
    pred_knn_sql = int(pred_knn_sql[0])

    # knn模型检测xss攻击流量
    feature_knn_xss = generate_url_xss(url)
    arr_knn_xss = [feature_knn_xss]
    clf_knn_xss = joblib.load("./model/knn_xss.model")
    pred_knn_xss = clf_knn_xss.predict(arr_knn_xss)
    pred_knn_xss = int(pred_knn_xss[0])

    # knn模型检测traversal攻击流量
    feature_knn_traversal = generate_url_traversal(url)
    arr_knn_traversal = [feature_knn_traversal]
    clf_knn_traversal = joblib.load("./model/knn_traversal.model")
    pred_knn_traversal = clf_knn_traversal.predict(arr_knn_traversal)
    pred_knn_traversal = int(pred_knn_traversal[0])

    # knn模型检测crlf注入流量
    feature_knn_crlf = generate_url_crlf(url)
    arr_knn_crlf = [feature_knn_crlf]
    clf_knn_crlf = joblib.load("./model/knn_crlf.model")
    pred_knn_crlf = clf_knn_crlf.predict(arr_knn_crlf)
    pred_knn_crlf = int(pred_knn_crlf[0])

    res = [pred_knn_normal, pred_knn_sql, pred_knn_xss, pred_knn_traversal, pred_knn_crlf]
    print("*" * 42)
    print("以下是KNN模型进行的检测报告")
    print("以下报告中1代表真，0代表假")
    print("预测为正常流量: %d" % pred_knn_normal)
    print("预测为sql注入攻击: %d" % pred_knn_sql)
    print("预测为xss攻击: %d" % pred_knn_xss)
    print("预测为目录遍历攻击: %d" % pred_knn_traversal)
    print("预测为crlf注入攻击: %d" % pred_knn_crlf)
    no = -1
    if res.count(1) != 1:           # 正例的数量大于1则认为是其他种类恶意流量
        print("系统判断该流量不属于上述五种中的任何一种，怀疑可能是其他种类恶意流量")
    else:
        no = res.index(1)           # 找到唯一一个正例的序号
        print("KNN模型预测该流量属于%s" % my_map[no])
    print("*" * 42)
    return no


def csv_knn_test(csv_dir):
    # knn模型检测normal注入攻击
    normal_test_matrix = generate_abnormal(csv_dir, "./data/user_test/user_test_knn_normal_matrix.csv", 1)
    clf_knn_normal = joblib.load("./model/knn_normal.model")
    feature_knn_normal = pd.read_csv(normal_test_matrix)
    arr_knn_normal = feature_knn_normal.values
    data = np.delete(arr_knn_normal, -1, axis=1)  # 删除最后一列
    pred_knn_normal = clf_knn_normal.predict(data)

    # knn模型检测sql注入攻击
    sql_test_matrix = generate_sql(csv_dir, "./data/user_test/user_test_knn_sql_matrix.csv", 1)
    clf_knn_sql = joblib.load("./model/knn_sql.model")
    feature_knn_sql = pd.read_csv(sql_test_matrix)
    arr_knn_sql = feature_knn_sql.values
    data = np.delete(arr_knn_sql, -1, axis=1)  # 删除最后一列
    pred_knn_sql = clf_knn_sql.predict(data)

    # knn模型检测xss注入攻击
    xss_test_matrix = generate_xss(csv_dir, "./data/user_test/user_test_knn_xss_matrix.csv", 1)
    clf_knn_xss = joblib.load("./model/knn_xss.model")
    feature_knn_xss = pd.read_csv(xss_test_matrix)
    arr_knn_xss = feature_knn_xss.values
    data = np.delete(arr_knn_xss, -1, axis=1)  # 删除最后一列
    pred_knn_xss = clf_knn_xss.predict(data)

    # knn模型检测traversal注入攻击
    traversal_test_matrix = generate_traversal(csv_dir, "./data/user_test/user_test_knn_traversal_matrix.csv", 1)
    clf_knn_traversal = joblib.load("./model/knn_traversal.model")
    feature_knn_traversal = pd.read_csv(traversal_test_matrix)
    arr_knn_traversal = feature_knn_traversal.values
    data = np.delete(arr_knn_traversal, -1, axis=1)  # 删除最后一列
    pred_knn_traversal = clf_knn_traversal.predict(data)

    # knn模型检测crlf注入攻击
    crlf_test_matrix = generate_crlf(csv_dir, "./data/user_test/user_test_knn_crlf_matrix.csv", 1)
    clf_knn_crlf = joblib.load("./model/knn_crlf.model")
    feature_knn_crlf = pd.read_csv(crlf_test_matrix)
    arr_knn_crlf = feature_knn_crlf.values
    data = np.delete(arr_knn_crlf, -1, axis=1)  # 删除最后一列
    pred_knn_crlf = clf_knn_crlf.predict(data)

    count_normal = 0                        # 正常流量的个数
    count_sql = 0                           # sql注入攻击的个数
    count_xss = 0                           # xss攻击的个数
    count_traversal = 0                     # 目录遍历攻击的个数
    count_crlf = 0                          # crlf注入攻击的个数
    count_other = 0                         # 其他恶意流量的个数
    count = len(pred_knn_normal)            # 测试的数据量
    count_dic = {-1: count_other, 0: count_normal, 1: count_sql, 2: count_xss, 3: count_traversal, 4: count_crlf}
    pred_all = [pred_knn_normal, pred_knn_sql, pred_knn_xss, pred_knn_traversal, pred_knn_crlf]

    for i in range(count):
        no = -1
        flag = 0
        nor = 0
        for j in range(5):
            if pred_all[j][i] == 1:
                no = j
                flag += 1
            if pred_all[j][i] == 0 and j != 0:
                nor += 1
            if pred_all[j][i] == 1 and j == 0:
                nor += 1
        if flag == 1:
            count_dic[no] += 1
        elif nor >= 2:
            count_dic[0] += 1
        elif flag > 1:
            count_dic[-1] += 1

    count_other = count_dic[-1]
    count_normal = count_dic[0]
    count_sql = count_dic[1]
    count_xss = count_dic[2]
    count_traversal = count_dic[3]
    count_crlf = count_dic[4]
    print("*" * 42)
    print("以下是KNN模型进行的检测报告")
    print("数据集一共包括%d条URL数据" % count)
    print("正常流量数量为: %d, 占比%.1f%%" % (count_normal, (count_normal / count) * 100))
    print("sql注入攻击数量为: %d, 占比%.1f%%" % (count_sql, (count_sql / count) * 100))
    print("xss攻击数量为: %d, 占比%.1f%%" % (count_xss, (count_xss / count) * 100))
    print("目录遍历攻击数量为: %d, 占比%.1f%%" % (count_traversal, (count_traversal / count) * 100))
    print("crlf注入攻击数量为: %d, 占比%.1f%%" % (count_crlf, (count_crlf / count) * 100))
    print("其他种类恶意流量数量为: %d, 占比%.1f%%" % (count_other, (count_other / count) * 100))
    print("*" * 42)


def csv_logistic_test(csv_dir):
    # logistic模型检测normal注入攻击
    normal_test_matrix = generate_abnormal(csv_dir, "./data/user_test/user_test_logistic_normal_matrix.csv", 1)
    clf_logistic_normal = joblib.load("./model/logistic_normal.model")
    feature_logistic_normal = pd.read_csv(normal_test_matrix)
    arr_logistic_normal = feature_logistic_normal.values
    data = np.delete(arr_logistic_normal, -1, axis=1)  # 删除最后一列
    pred_logistic_normal = clf_logistic_normal.predict(data)

    # logistic模型检测sql注入攻击
    sql_test_matrix = generate_sql(csv_dir, "./data/user_test/user_test_logistic_sql_matrix.csv", 1)
    clf_logistic_sql = joblib.load("./model/logistic_sql.model")
    feature_logistic_sql = pd.read_csv(sql_test_matrix)
    arr_logistic_sql = feature_logistic_sql.values
    data = np.delete(arr_logistic_sql, -1, axis=1)  # 删除最后一列
    pred_logistic_sql = clf_logistic_sql.predict(data)

    # logistic模型检测xss注入攻击
    xss_test_matrix = generate_xss(csv_dir, "./data/user_test/user_test_logistic_xss_matrix.csv", 1)
    clf_logistic_xss = joblib.load("./model/logistic_xss.model")
    feature_logistic_xss = pd.read_csv(xss_test_matrix)
    arr_logistic_xss = feature_logistic_xss.values
    data = np.delete(arr_logistic_xss, -1, axis=1)  # 删除最后一列
    pred_logistic_xss = clf_logistic_xss.predict(data)

    # logistic模型检测traversal注入攻击
    traversal_test_matrix = generate_traversal(csv_dir, "./data/user_test/user_test_logistic_traversal_matrix.csv", 1)
    clf_logistic_traversal = joblib.load("./model/logistic_traversal.model")
    feature_logistic_traversal = pd.read_csv(traversal_test_matrix)
    arr_logistic_traversal = feature_logistic_traversal.values
    data = np.delete(arr_logistic_traversal, -1, axis=1)  # 删除最后一列
    pred_logistic_traversal = clf_logistic_traversal.predict(data)

    # logistic模型检测crlf注入攻击
    crlf_test_matrix = generate_crlf(csv_dir, "./data/user_test/user_test_logistic_crlf_matrix.csv", 1)
    clf_logistic_crlf = joblib.load("./model/logistic_crlf.model")
    feature_logistic_crlf = pd.read_csv(crlf_test_matrix)
    arr_logistic_crlf = feature_logistic_crlf.values
    data = np.delete(arr_logistic_crlf, -1, axis=1)  # 删除最后一列
    pred_logistic_crlf = clf_logistic_crlf.predict(data)

    count_normal = 0                        # 正常流量的个数
    count_sql = 0                           # sql注入攻击的个数
    count_xss = 0                           # xss攻击的个数
    count_traversal = 0                     # 目录遍历攻击的个数
    count_crlf = 0                          # crlf注入攻击的个数
    count_other = 0                         # 其他恶意流量的个数
    count = len(pred_logistic_normal)            # 测试的数据量
    count_dic = {-1: count_other, 0: count_normal, 1: count_sql, 2: count_xss, 3: count_traversal, 4: count_crlf}
    pred_all = [pred_logistic_normal, pred_logistic_sql, pred_logistic_xss, pred_logistic_traversal, pred_logistic_crlf]

    for i in range(count):
        no = -1
        flag = 0
        nor = 0
        for j in range(5):
            if pred_all[j][i] == 1:
                no = j
                flag += 1
            if pred_all[j][i] == 0 and j != 0:
                nor += 1
            if pred_all[j][i] == 1 and j == 0:
                nor += 1
        if flag == 1:
            count_dic[no] += 1
        elif nor >= 2:
            count_dic[0] += 1
        elif flag > 1:
            count_dic[-1] += 1

    count_other = count_dic[-1]
    count_normal = count_dic[0]
    count_sql = count_dic[1]
    count_xss = count_dic[2]
    count_traversal = count_dic[3]
    count_crlf = count_dic[4]

    print("*" * 42)
    print("以下是逻辑回归模型进行的检测报告")
    print("数据集一共包括%d条URL数据" % count)
    print("正常流量数量为: %d, 占比%.1f%%" % (count_normal, (count_normal / count) * 100))
    print("sql注入攻击数量为: %d, 占比%.1f%%" % (count_sql, (count_sql / count) * 100))
    print("xss攻击数量为: %d, 占比%.1f%%" % (count_xss, (count_xss / count) * 100))
    print("目录遍历攻击数量为: %d, 占比%.1f%%" % (count_traversal, (count_traversal / count) * 100))
    print("crlf注入攻击数量为: %d, 占比%.1f%%" % (count_crlf, (count_crlf / count) * 100))
    print("其他种类恶意流量数量为: %d, 占比%.1f%%" % (count_other, (count_other / count) * 100))
    print("*" * 42)


def user_test():
    while(1):
        print("*" * 42)
        print("请选择是进行单个URL流量检测或者csv文件流量检测")
        print("1.单个URL流量检测      2.csv文件流量检测      3.退出")
        print("*" * 42)
        choose1 = input()
        if int(choose1) == 1:
            print("请输入要检测的URL")
            url = input()
            res_knn = url_knn_test(url)
            res_logistic = url_logistic_test(url)
            if res_knn == -1 and res_logistic == -1:
                print("综合上述两个模型，系统判断该流量不属于上述五种中的任何一种，怀疑可能是其他种类恶意流量")
            elif res_knn == res_logistic:
                print("综合上述两个模型，系统判断该流量属于%s" % my_map[res_knn])
            else:
                print("综合上述两个模型，系统判断该流量可能属于%s, 也有可能属于%s, 请用户自行判断" % (my_map[res_knn], my_map[res_logistic]))
            print("*" * 42)
            print("系统反馈调查表:")
            print("请告诉系统此次检测是否准确")
            print("0: 不准确   1: 准确")
            print("十分感谢您的反馈，系统会根据此次反馈进行自我完善")
            print("*" * 42)
            feedback = input()
            # 将用户输入的url送到训练集中
            if int(feedback) == 1 and res_knn == res_logistic and res_knn != -1:
                with open(my_map_knn_dir[res_knn], 'a', newline='') as file:
                    writer = csv.writer(file)
                    # 新数据
                    new_row = [url]
                    # 写入新数据
                    writer.writerow(new_row)
                file.close()
                with open(my_map_logistic_dir[res_logistic], 'a', newline='') as file:
                    writer = csv.writer(file)
                    # 新数据
                    new_row = [url]
                    # 写入新数据
                    writer.writerow(new_row)
                file.close()
        elif int(choose1) == 2:
            print("请输入要检测的csv文件路径")
            csv_dir = input()
            csv_knn_test(csv_dir)
            csv_logistic_test(csv_dir)
        elif int(choose1) == 3:
            break
        else:
            print("非法输入")
            continue
