* Fix crasher in either chaff or winnow
* Make chaff size relative to message size without giving away message size
  (perhaps add/substract an offset from the message size and create random
  chaff sizes based on that)
* Use crypto/rand for chaff sizing or at least seed math/rand
* Add ascii/dictionary chaff
