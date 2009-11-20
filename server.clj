(clojure.core/ns malwut.server
                 (:use compojure)
                 (:use clojure.contrib.pprint)
                 (:use clojure.contrib.str-utils)
                 (:use malwut.common))

(defn- get-td)

(defn malware-view
  "View for displaying malware."
  [md5s]
  (let [malware (apply lookup-by-md5 md5s)]
    (html
     [:head [:title "Malware Results"]
      [:style {:type "text/css"}
       "tbody tr td {
      background-color: #eee;
    }
      thead tr td {
        font-weight: bold;
        background-color: #00ffff;
    }
    tbody tr.odd  td {
      background-color: #fff;
    }"]]
     [:form {:method "post"}
      "MD5s (comma separated): "
      [:input {:name "md5s", :type "text"}]
      [:br]
      [:input {:type "submit" :value "Lookup"}]]
     [:br]
     [:table
      [:thead
       [:tr
        [:td "class"]
        [:td "name"]
        [:td "tags"]
        [:td {:align "right"} "variant number"]]]
      [:tbody
       (map (fn [m]
              [:tr
               [:td (:class m)]
               [:td (:name m)]
               [:td (cl-format nil "~{~a~^, ~}" (:tags m))]
               [:td {:align "right"} (:variant m)]])
            malware)]])))

(defroutes my-app
  (GET "/"
    (html [:h1 "Malware Lookup"]
          (malware-view nil)))
  (POST "/"
    (html [:h1 "Malware Results"]
          (malware-view (re-split #"," (params :md5s)))))
  (ANY "*"
    (page-not-found)))

(defn start-server
  "Start compojure server."
  []
  (run-server {:port 8080}
              "/*" (servlet my-app)))
