# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn import neighbors
from featurepossess import generate_xss
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
import joblib


def knn_xss_train():
    xss_matrix = generate_xss("./data/knn/xss/xss_train.csv", "./data/knn/xss/xss_matrix.csv", 1)
    xss_normal_matrix = generate_xss("./data/knn/xss/normal_train.csv", "./data/knn/xss/xss_normal_matrix.csv", 0)

    # 将两个csv文件合并在一个csv文件中
    df = pd.read_csv(xss_matrix)                                     # 读取CSV格式的特征矩阵文件，并将其存储到一个名为df的Pandas数据框中
    df.to_csv("./data/knn/xss/xss_all_matrix.csv", encoding="utf_8_sig", index=False)      # _sig表示该编码格式带有 BOM（Byte Order Mark）头，用于在文本编辑器中正确显示中文字符
    df = pd.read_csv(xss_normal_matrix)
    df.to_csv("./data/knn/xss/xss_all_matrix.csv", encoding="utf_8_sig", index=False, header=False, mode='a+')

    feature_max = pd.read_csv('./data/knn/xss/xss_all_matrix.csv')
    arr = feature_max.values                                # 使用values属性将feature_max数据框转换为一个NumPy数组arr，其中每行代表一个样本的特征向量
    data = np.delete(arr, -1, axis=1)                       # 删除最后一列

    target = arr[:, 3]                                      # 将arr数组的第7列（即标签列）提取出来
    # 随机划分训练集和测试集
    # random_state=3 表示随机种子，这个参数用于保证每次运行代码时得到的训练集和测试集的划分结果都是相同的
    # 函数返回一个长度为4的元组，包含划分后的训练集数据、测试集数据、训练集标签和测试集标签
    train_data, test_data, train_target, test_target = train_test_split(data, target, test_size=0.3, random_state=3)
    # 模型
    knn = neighbors.KNeighborsClassifier(algorithm='ball_tree')   # 创建分类器对象，k值默认为5
    knn.fit(train_data, train_target)                             # 训练模型
    joblib.dump(knn, './model/knn_xss.model')       # 将训练好的 knn k-近邻分类器模型保存到指定路径下的 knn.model 文件中，以便之后可以快速地加载模型进行预测
    # print("knn_xss model has been saved to 'model/knn_xss.model'")
    # knn = joblib.load('svm.model')
    y_pred = knn.predict(test_data)                                 # y_pred 是一个一维数组，包含了测试数据中每个样本的预测结果
    # print("y_pred:%s" % y_pred)                                   # 输出y_pred数组
    # print("test_target:%s" % test_target)
    # Verify
    print("*" * 42)
    print("KNN模型XSS攻击训练结果报告")
    print("本次训练共有%d条数据用于测试" % len(y_pred))
    print('准确度为:{:.1%}' .format(metrics.precision_score(y_true=test_target, y_pred=y_pred)))  # 准确率
    print('召回率为:{:.1%}' .format(metrics.recall_score(y_true=test_target, y_pred=y_pred)))     # 召回率
    print('F1的值为:{:.1%}' .format(metrics.f1_score(y_true=test_target, y_pred=y_pred)))         # F1的值
    print("混淆矩阵如下所示:")
    print(metrics.confusion_matrix(y_true=test_target, y_pred=y_pred))  # 混淆矩阵
    print("*" * 42)
