(clojure.core/ns malwut.common)
;;;; Contains common structs to use
;;;; across all of malwut

(def classes #{"trojan" "worm" "exploit" "w32" "dialer"})

(defstruct maltry :class :name :project :path :md5 :tags :varnum)