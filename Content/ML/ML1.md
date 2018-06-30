Classification Learning(分类学习)

Regression Learning(回归；退化；逆行；复原)
> 变量之间的相互关系可以分为确定性和非确定性两大类，前者存在明显的函数关系，如线性函数。后者的变量之间存在关系但不完全确定，在某种随机干扰下产生统计关系们无法获得精确的数学函数关系。对于存在统计关系的变量，通过大量试验获取相关统计数据，并构造目标函数并逼近该关系，即回归学习。

Supervised Learning(有监督的)
> 监督学习：通过已有的一部分输入数据与输出数据之间的对应关系，生成一个函数，将输入映射到合适的输出，例如分类。

un-Supervised Learning(无监督的)
> 非监督学习：直接对输入数据集进行建模，例如聚类。

semi-Supervised Learning(半监督的)
> 半监督学习：综合利用有类标的数据和没有类标的数据，来生成合适的分类函数。

Batch Learning（批量学习）
> batch越小，训练完一组的时间越短，但可能需要更多的步数接近局部最佳值，从大体效果来说，batch对结果影响应该不大。

Online Learning （在线学习）
> 在线学习（online learning），按照顺序，循序的学习，不断的去修正模型，进行优化。

Active Learning （主动学习）
> 有的时候，有类标的数据比较稀少而没有类标的数据是相当丰富的，但是对数据进行人工标注又非常昂贵，这时候，学习算法可以主动地提出一些标注请求，将一些经过筛选的数据提交给专家进行标注。


感知机学习算法 Perceptron Learning Algorithm (PLA)

霍夫丁不等式

结论大概近似正确（probably approximately correct PAC）。



