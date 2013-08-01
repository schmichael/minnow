minnow 鯫
========

Winnow and chaff example in golang


To run the server: ``go run winnow/winnow.go -secret="toomanysecrets"``

To run the test client:

```bash
go run chaff/chaff.go \
    -secret toomanysecrets \
    -message "Anybody want to shut down the Federal Reserve?"
```


See: http://people.csail.mit.edu/rivest/Chaffing.txt

And: http://en.wikipedia.org/wiki/Chaffing_and_winnowing

![](http://i.imgur.com/cuwkJr1.gif)
