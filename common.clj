(clojure.core/ns malwut.common
                 (:use clojure.contrib.seq-utils)
                 (:import [java.io File])
                 (:import [org.apache.commons.io FileUtils]))
;;;; Contains common structs to use
;;;; across all of malwut

(def classes #{"trojan" "worm" "exploit" "w32" "dialer"})

(defstruct maltry :class :name :project :path :md5 :tags :variant)

;; you should make this lazy
;; so it's "more" efficient
(defn- drop-variant-dupes
  "Drop variant duplicates (samples with different md5s, but the
same name and variant number)."
  [db]
  (loop [unique-var {}
         malware {}
         db db]
    (if (empty? db)
      malware
      (let [sample (second (first db))
            name (.toLowerCase (:name sample))
            var (:variant sample)
            ; we want to treat this (even if its empty) as a set
            var-set (or (get unique-var name) #{})]
        (if (some #{var} var-set)
          (recur unique-var malware (rest db))
          (recur (assoc unique-var name (conj var-set var))
                 (assoc malware (:md5 sample) sample)
                 (rest db)))))))

(defn get-n-by-name
  "Get n samples from the family name"
  [n db & names]
  (let [no-var-dupes (drop-variant-dupes db)]
    ; this is real messy
    (apply hash-map
           (flatten
            (map
             #(take n (filter (fn [malware] (.equalsIgnoreCase % (:name (second malware)))) no-var-dupes))
             names)))))

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