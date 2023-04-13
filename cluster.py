import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

def cluster_urls(file_path, num_clusters=3, random_state=42):
    # 读取CSV文件并将URL向量化
    df = pd.read_csv(file_path, header=None, names=['url'])
    df = df.dropna()
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(df['url'].values.astype('U'))

    # 使用Silhouette分析选择最佳聚类数
    sil_scores = []
    for n_clusters in range(2, 10):
        kmeans = KMeans(n_clusters=n_clusters, random_state=random_state)
        kmeans.fit(X)
        labels = kmeans.labels_
        sil_scores.append(silhouette_score(X, labels))

    best_num_clusters = np.argmax(sil_scores) + 2

    # 使用最佳聚类数进行KMeans聚类
    kmeans = KMeans(n_clusters=best_num_clusters, random_state=random_state)
    kmeans.fit(X)
    df['cluster'] = kmeans.labels_

    # 使用IsolationForest进行异常值检测
    clf = IsolationForest(random_state=random_state)
    clf.fit(X)
    df['outlier'] = clf.predict(X)

    # 过滤掉异常值和无效值
    df = df[df['outlier'] == 1].dropna()

    # 可视化聚类结果
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    colors = ['blue', 'green', 'red', 'cyan', 'magenta', 'yellow', 'black', 'white', 'orange', 'gray']
    for i, c in enumerate(df['cluster'].unique()):
        df_cluster = df[df['cluster'] == c]
        ax.scatter(df_cluster.iloc[:, 0], df_cluster.iloc[:, 1], df_cluster.iloc[:, 2], c=colors[i],
                   label='Cluster {}'.format(c))
    ax.set_title('URL Clusters')
    ax.set_xlabel('X Label')
    ax.set_ylabel('Y Label')
    ax.set_zlabel('Z Label')
    ax.legend()
    plt.show()


cluster_urls("./data/cluster.csv")
