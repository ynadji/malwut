(clojure.core/ns malwut.offensive-computing
                 (:require [com.twinql.clojure.http :as http])
                 (:import (org.apache.http.impl.client AbstractHttpClient))
                 (:require [clojure.xml :as xml])
                 (:use clojure.contrib.def)
                 (:use clojure.contrib.zip-filter.xml))

(def *cookie-store* nil)

(defmacro with-http-bindings
  "Binds the keys from the result of the HTTP request, executing forms."
  [keys http-form & forms]
  `(let [{:keys ~keys} ~http-form]
     ~@forms))

(defn ok? [res]
  (pr-str res)
  true)

(defn- check?
  "Checks both an HTTP status code and a JSON body."
  [code content]
  (and (>= code 200)
       (< code 300)))

(defn- plog
  [user pass]
  (http/post "http://www.offensivecomputing.net/?q=node&destination=node"
             :query {"edit[name]" user
                     "edit[pass]" pass
                     "op" "Log in"
                     "edit[form_id]" "user_login_block"
                     }))

(defn login
  "Login to offensivecomputing.net"
  [user pass]
  (with-http-bindings
    [code content #^AbstractHttpClient client]
    (http/post "http://www.offensivecomputing.net/?q=node&destination=node"
               :query {"edit[name]" user
                       "edit[pass]" pass
                       "op" "Log in"
                       "edit[form_id]" "user_login_block"}
               :cookie-store *cookie-store*)
    [content (.getCookieStore client)]))

(defmacro with-login [[user pass] & body]
  `(let [[response# cookie-store#] (login ~user ~pass)]
     (if response#
       ;; Great!
       (binding [*cookie-store* cookie-store#]
         ~@body)
       (throw (new Exception "Login failed.")))))

(defnk search
  "Search offensivecomputing.net"
  [user pass query :slow-search true]
  (with-login [user pass]
    (http/post "http://www.offensivecomputing.net/?q=ocsearch"
               :as :string
               :cookie-store *cookie-store*
               :query {
                       "search" query
                       "slowsearch" (if slow-search "on" "off")
                      })))

(defn startparse-tagsoup
  "startparse that uses tagsoup"
  [s ch]
  (doto (org.ccil.cowan.tagsoup.Parser.)
    (.setContentHandler ch)
    (.parse s)))