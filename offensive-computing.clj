(clojure.core/ns malwut.offensive-computing
                 (:require [com.twinql.clojure.http :as http])
                 (:import (org.apache.http.impl.client AbstractHttpClient))
                 (:require [clojure.xml :as xml])
                 (:require [clojure.contrib.zip-filter :as zf])
                 (:use [clojure.contrib.zip-filter.xml :only (xml-> attr)])
                 (:use [clojure.zip :only (xml-zip node)])
                 (:use clojure.contrib.def))

(def *cookie-store* nil)

(defmacro with-http-bindings
  "Binds the keys from the result of the HTTP request, executing forms."
  [keys http-form & forms]
  `(let [{:keys ~keys} ~http-form]
     ~@forms))

(defn- check?
  "Checks for passing HTTP status code"
  [code content]
  (and (>= code 200)
       (< code 300)))

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
  "Logs in, binds cookie to *cookie-store*."
  `(let [[response# cookie-store#] (login ~user ~pass)]
     (if response#
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
               :query {"search" query
                       "slowsearch" (if slow-search "on" "off")})))

(defn startparse-tagsoup
  "startparse that uses tagsoup"
  [s ch]
  (doto (org.ccil.cowan.tagsoup.Parser.)
    (.setContentHandler ch)
    (.parse s)))

(defn parse
  "Parse out info from search results."
  [html]
  (xml-zip
   (xml/parse (org.xml.sax.InputSource.
               (java.io.StringReader. html))
              startparse-tagsoup)))