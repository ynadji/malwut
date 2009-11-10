(clojure.core/ns malwut.reader
		 (:use clojure.contrib.duck-streams)
		 (:use clojure.contrib.str-utils)
		 (:use malwut.common))

(defn- get-class
  "Get class from clamav log output."
  [tag]
  (first tag))

(defn- get-name
  "Get malware name from clamav log output."
  [tag]
  (second tag))

(defn- get-varnum
  "Get malware variant number (not terribly important
but good to have nonetheless"
  [tag]
  (if (empty? tag)
    0
    (let [n (first tag)]
     (if (re-matches #"\d+" n)
       (Integer. n)
       (recur (rest tag))))))

(defn- parse-clamav-line
  "Parse single line from clamav log output."
  [line]
  (let [p (rest (first (re-seq #"(.+?)([a-fA-F0-9]{32}): (.+?) FOUND" line)))
	tags (re-split #"\.|-" (nth p 2))]
    (struct maltry (get-class tags) (get-name tags) "2010-oakland-malware"
            (first p) (second p) (set tags) (get-varnum (reverse tags)))))

(defn read-clamav
  "Reads report from Clam AV, parses input. Returned
   information can be added to malwut db"
  [logfile]
  (let [malware (drop-last
		 10 (drop
		     3 (read-lines logfile)))]
    (map #(parse-clamav-line %) malware)))

(defn read-and-save-clamav
  "Reads Clam AV report, dumps it to a nice DB that Clojure can
read in easily."
  [logfile dumpdb]
  (spit dumpdb (pr-str (read-clamav logfile))))

(defn load-clamav
  "Read in parsed Clam AV report."
  [dumpdb]
  (read-string (slurp dumpdb)))