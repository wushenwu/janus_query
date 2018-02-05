# 更方便的处理Janus数据

Janus作为移动安全威胁数据平台，目前提供了大量的元数据。但对于用户更为重要的是，能在此基础上进行更为灵活的数据再加工、分析。



本程序在平台已经提供的api基础上，进行了再封装，主要服务于以下几个场景：

## 1. 搜索应用

```Python
# directly query the keyword, without indicating the type
python janus_query_front.py 04092efc88d29f7a7b67027d0b8dde58f81e8afb    

# directly query the keyword, without indicating the type
python janus_query_front.py com.example.helloworldMobile.SmsReceiver    
    
# query the specified key:value
python janus_query_front.py 'receiver:"com.example.helloworldMobile.SmsReceiver"'  

# 
python janus_query_front.py query.txt

query.txt looks like
04092efc88d29f7a7b67027d0b8dde58f81e8afb
com.example.helloworldMobile.SmsReceiver 
receiver:"com.example.helloworldMobile.SmsReceiver"
```

模仿前台调用，查询符合特定条件的应用。

在使用时，需要在janus_query_front.py中填充自己的Cookie, 类似：

```
cookie = 'Cookie: Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1516233831,1517054214,1517193475,zzzzzzzz; LANG=cn; PGSessionId=d5bc2b09-e71c-44c0-b834-yyyyyyyy;                                               Hm_lpvt_2d9a49e839e5ceb193269aefa897ae80=xxxxx
```

平台提供了非常丰富的前台查询操作（http://cloud.appscan.io/search-app.html#type=app&page=1），对应的后台api类似如下：

```
http://cloud.appscan.io/api/search?type=app&q=
```

这些对应关系，都可以通过抓包获取到。



## 2. 获取样本基础信息

```
python janus_query_manifest.py {sha1}

python janus_query_manifest.py file_contains_sha1.txt

对应api:
http://cloud.appscan.io/api/app/%s?sha1=%s

API_TYPES = ["files", "receiver", "activity", "service","strings", "cert", "permission",]# "provider"]
```

查询指定sha1 样本的基础信息（元数据），如files, receiver等。



同样需要在janus_query_manifest.py中填充自己的Cookie，类似：

```
cookie = 'Cookie: PGSessionId=d5bc2b09-e71c-44c0-b834-4esfsfsfsfdsdsf; Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1517193475,1517279958,1517826129,1517827132;                                                 Hm_lpvt_2d9a49e839e5ceb193269aefa89ssfsjfsfjs'
```



## 3. 查询规则匹配结果

上面janus_query_front.py 可以用于简单的查询场景。而复杂的查询场景，可以借助规则扫描。

比如 http://cloud.appscan.io/monitor.html?id=5a6ff18b027238119e56b9b2 为例：

```
python janus_query_task.py 5a6ff18e027238119e56b9be

对应的api 为http://cloud.appscan.io/api/analysis/v2/task/app?id=%s
```

同样需要填充janus_query_task.py 中的Cookie, 类似：

```
Cookie: PGSessionId=d5bc2b09-e71c-44c0-b834-xxxxx; Hm_lvt_2d9a49e839e5ceb193269aefa897ae80=1517193475,1517279958,1517826129,1517827132; Hm_lpvt_2d9a49e839e5ceb193269aefa89yyyyyyy
```



## 4. 下载应用

```
python janus_download.py {sha1}

对应的api http://cloud.appscan.io/api/cloud/download?sha1=
```

需要在janus_download.py中填充Cookie。



以上，对高频的操作场景进行了基本封装，希望更方便的获取数据、加工数据，让Janus的数据更好的发挥价值。

此外，上述程序可以借助python rq 等进行更优雅的实现。



源码详见：

https://github.com/wushenwu/janus_query

