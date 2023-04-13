from user_test import user_test
from test import test
from Normal_KNN import knn_normal_train
from Normal_Logistic import logistic_normal_train
from Sql_KNN import knn_sql_train
from Sql_Logistic import logistic_sql_train
from Xss_KNN import knn_xss_train
from Xss_Logistic import logistic_xss_train
from Traversal_KNN import knn_traversal_train
from Traversal_Logistic import logistic_traversal_train
from CRLF_KNN import knn_crlf_train
from CRLF_Logistic import logistic_crlf_train
from train import train

function_knn_dic = {1: knn_normal_train, 2: knn_sql_train, 3: knn_xss_train,
                    4: knn_traversal_train, 5: knn_crlf_train}

function_logistic_dic = {1: logistic_normal_train, 2: logistic_sql_train, 3: logistic_xss_train,
                         4: logistic_traversal_train, 5: logistic_crlf_train}

if __name__ == "__main__":
    while(1):
        print("*" * 42)
        print("欢迎使用基于机器学习的恶意流量检测系统")
        print("请选择要使用的功能")
        print("1. 训练数据集并测试      2. 使用本地测试集进行测试")
        print("3. 使用用户提供URL进行测试      4. 退出")
        print("*" * 42)
        choose = input()
        if int(choose) == 4:
            break
        elif int(choose) == 1:
            train()
        elif int(choose) == 2:
            test()
        elif int(choose) == 3:
            user_test()
        else:
            break
