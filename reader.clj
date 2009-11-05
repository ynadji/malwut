(clojure.core/ns malwut.reader
		 (:use clojure.contrib.duck-streams)
		 (:use clojure.contrib.str-utils)
		 (:use malwut.common))

(defn- parse-clamav-line
  "Parse single line from clamav log output."
  [line]
  (let [p (rest (first (re-seq #"(.+?)([a-fA-F0-9]{32}): (.+?) FOUND" line)))]
    (struct maltry "class" "name" "2010-oakland-malware" (first p) (second p) (nth p 2))))

(defn read-clamav
  "Reads report from Clam AV, parses input. Returned
   information can be added to malwut db"
  [logfile]
  (let [malware (drop-last
		 10 (drop
		     3 (read-lines logfile)))]
    (map #(parse-clamav-line %) malware)))