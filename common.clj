(clojure.core/ns malwut.common
                 (:import [java.io File])
                 (:import [org.apache.commons.io FileUtils]))
;;;; Contains common structs to use
;;;; across all of malwut

(def classes #{"trojan" "worm" "exploit" "w32" "dialer"})

(defstruct maltry :class :name :project :path :md5 :tags :varnum)

(defn get-n-by-name
  "Get n samples from the family name"
  [n name db]
  (take n (filter #(.equalsIgnoreCase name (:name (second %))) db)))

(defn dump-malware-to-dir
  "Given a list of samples, create a malware directory."
  [malware output-dir]
  (do
    (let [outdir (File. output-dir)]
      (.mkdir outdir)
      (doseq [sample malware]
        (let [infile (File. (str (:path (second sample)) (first sample)))]
          (FileUtils/copyFileToDirectory infile outdir))))))

(defn lookup-by-md5
  "Lookup piece of malware by md5"
  [malware & md5s]
  (map #(get malware %) md5s))