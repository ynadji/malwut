(clojure.core/ns malwut.offensive-computing
                 (:require [com.twinql.clojure.http :as http])
                 (:require [clojure.xml :as xml])
                 (:use clojure.contrib.zip-filter.xml))

(def *cookie-store* nil)

(defmacro with-http-bindings
  "Binds the keys from the result of the HTTP request, executing forms."
  [keys http-form & forms]
  `(let [{:keys ~keys} ~http-form]
     ~@forms))

(defn startparse-tagsoup
  "startparse that uses tagsoup"
  [s ch]
  (doto (org.ccil.cowan.tagsoup.Parser.)
    (.setContentHandler ch)
    (.parse s)))

(defn login
  "Login to offensivecomputing.net"
  [user pass]
  (:content (http/post "http://www.offensivecomputing.net/?q=node&destination=node"
                       :query {"edit[name]" user
                               "edit[pass]" pass
                               "op" "Log in"
                               "edit[form_id]" "user_login_block"}
                       :as :string
                       :cookie-store *cookie-store*)))