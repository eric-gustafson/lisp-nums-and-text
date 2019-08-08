;;;; ip.lisp
(in-package #:numex)

(defun fixnum-info ()
  "Returns :little-endian or :bigendian which should be found in the
*features* list for the numerical disposition of hte hardware on the
machine that is running the computation"
  #+(or little-endian) (return-from fixnum-info :little-endian)
  #+(or big-endian) (return-from fixnum-info :big-endian)
  )

(defvar *hw-numerical-type* (fixnum-info)
  "A dynamic variable that controls how IP addresses and numbers are
  computed.
  The code could be performing a computation for a target for
  instance, and we want to ignore the integer-hw-type of the machine
  that is doing the computation."
  )

(defmethod addr->dotted ((obj list))
  "Convert the address into dotted string"
  (format nil "~{~A~^.~}" obj)  
  )

(defmethod addr->dotted ((obj vector))
  "Convert the address into dotted string"
  (let ((n (length obj)))
    (with-output-to-string
	(*standard-output*)
      (loop :for i :below n 
	 :when (> i 0) :do (princ ".")
	 :do (princ (elt obj i)))
      )))

(defmethod addr->dotted ((obj number))
  (addr->dotted (num->octets obj)))

(defun print-ipaddr (obj stream)
  ;; only handles ipv4 at the moment
  (labels ((doit (a b c d)
	     (print-unreadable-object
		 (obj stream :type t)
	       (format stream "~a.~a.~a.~a" a b c d)
	       )))
    (trivia:match
	obj
      ((vector a b c d) (doit a b c d))
      ((list a b c d) (doit a b c d))
      (otherwise
       (error "Unexpected parameter ~a" obj)))
    )
  )

;; Can the name be WORSE?  Makes me thing network address, like big endian
(defun na->list (n)
  ;; Takes a native integer fixnum, like from a packet sniffer
  (loop for i from 0 upto 3
     collect (ldb (byte 8 (* 8 i)) n)))

(defun make-cidr-mask (ncidr-bits)
  (loop
     :with mask = #x80000000
     :repeat (- ncidr-bits 1)
     :do
     (setf mask (logior mask (ash mask -1)))
     :finally (return mask)))

(defparameter *ip-cidr-scanner*
  (ppcre:create-scanner
   '(:sequence
     (:register (:SEQUENCE (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
		 (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
		 (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
		 (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) ))
     #\/
     (:register (:GREEDY-REPETITION 1 NIL :DIGIT-CLASS)))))

(defparameter *ip-scanner*
  (ppcre:create-scanner
   '(:SEQUENCE (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
     (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
     (:GREEDY-REPETITION 1 3 :DIGIT-CLASS) #\.
     (:GREEDY-REPETITION 1 3 :DIGIT-CLASS))))


(defun dotted->vector (str)
  "Take a number in dotted notation and return a vector representation."
  (declare (type string str))
  (trivia:match
      str
    ((trivia.ppcre:ppcre (*ip-cidr-scanner*) ip _)
     ;; 172.21.18.6/24
     (dotted->vector ip))
    ((trivia.ppcre:ppcre (*ip-scanner*))
     (let ((v (serapeum:vect)))
       (loop :for num string in (split-sequence #\. str)
	  :do (vector-push-extend  (parse-integer num) v))
       v
       )
     )
    )
  )

(defun dotted->list (str)
  (declare (type string str))
  (coerce (dotted->vector str) 'list)
  )

(defun parse-dotted (str)
  "Calles dotted->list"
  (dotted->list str))

(defun dotted->num (str)
  "Turn a dotted representation in network byte order (big-endian)
into a number. x86 is little-endian.  RBPI is usually little-endian."
  (octets->num (dotted->vector str)) )

(defun bits-needed (num)
  "Calculates how many octets needed to store the number"
  (loop
     :for i integer :from 0
     :while (> num 0)
     :do (setf num (ash num -1))
     :finally (return-from bits-needed i)
     )
  )

(defun hostnum->octets (num &key (num-octets 4))
  "Takes a lisp number (machine) and turns it into an octet vector in big-endian"
  (let* ((slen num-octets)
	 (seq (make-array slen)))
    (loop :for i integer from 0 below slen
       ;;:while (> num  0)
       :do
       (setf (elt seq (- slen i 1)) (ldb (byte 8 (* 8 i)) num))
       ;;(setf num (ash num -8)) ;; shift right
       )
    seq)
  )

    
(defun num->octets (num &key (endian :big-endian) (length 4))
  ;; (num->octets 259) => #(0 0 1 3)
  ;; (num->octets 256 :endian :little) => #(3 1 0 0)
  ;; Defaults to network byte order
  "Takes a number and returns that number as a list of octets in either big or little endian"
  (ecase endian
    ((:big-endian :network :big :b :n :net)
     (hostnum->octets num :num-octets length)
     )
    ((:little-endian :little :l)
     (reverse (hostnum->octets num :num-octets length))
     )
    ))

(defun hexstring->octets (str)
  (let ((ours (copy-sequence 'string str)))
    (mapcar
     #'(lambda(hstr)
	 (parse-integer hstr :radix 16))
     (serapeum:batches (delete-if #'(lambda(c) (find c (vector #\:))) ours) 2))
    )
  )

(defun num->dotted (num &key (length 4))
  (format nil "~{~a~^.~}" (coerce (num->octets num :length length) 'list))
  )

(defun nbo-octet->nbo-integer (octet-lst)
  ;; Takes an octet list and makes a 32 bit network byte order
  ;; integer.  Most used for IPV4 addresses.
  (let ((nbo-num 0))
    (loop
       :for i upto 3
       :for x in octet-lst
       :do
       (setf (ldb (byte 8 (* i 8)) nbo-num) x))
    nbo-num))

(defun nbo-hex-string (hex)
  (loop :for i :from 0 :by 2 :upto 6
     :collect
     (parse-integer (subseq hex i (+ i 2)) :radix 16))
  )

(defun machine-fixnum-string->octet-list (str)
  ;; convert a string into a sequnce of octets.  The string is in
  ;; machine order.
  #-(or little-endian)(string->octet-list d)
  #+(or little-endian)(reverse (string->octet-list str))
  )

(defun net-octets->host-octets (seq)
  "network byte order is just reversing an octect list"
  (check-type seq sequence)
  #+(or big-endian) seq
  #-(or big-endian) (reverse seq)
  )

(defun host-octets->net-octets (seq)
  (check-type seq sequence)
  #+(or big-endian) seq
  #-(or big-endian) (reverse seq)
  )

(defun _octets->num (seq)
  (check-type seq sequence)
  ;; shift right
  (reduce #'(lambda(acc octet)
	      ;; This is multiplication most places??  In C
	      ;; bitwise-shifts are usually considered an arithmetic
	      ;; operation, but not always? (worse is better)
	      (setf acc (ash acc 8)) ;; shift left (up) 8
	      (setf (ldb (byte 8 0) acc) octet)
	      acc)
	  seq
	  :initial-value 0))

(defun octets->num (oct-seq &key (endian :big-endian))
  "Turn a series of octets into a machine number.  The endian keyword parameter describes the endianess of the oct-seq parameter."
  (check-type oct-seq sequence)  
  (ecase
      endian
    ((:big-endian :network :big :b :n :net)
     (_octets->num  oct-seq)
     )
    ((:little-endian :little :l)
     (_octets->num (reverse oct-seq))
     )
    )
  )

(defun seq->num (seq &key (endian :big-endian))
  (octets->num seq :endian endian))

(defun string->octet-list (str)
  (declare (type string str))
  (let* ((len (length str)))
    (declare (type integer len))
    (reverse
     (loop :for i integer :from len :downto 0 :by 2
	:when (> i 0)
	:collect (parse-integer str :start (- i 2) :end i :radix 16)
	))))

(defun octet-list->hexstr (addr)
  "Send in any sequence of octets, and this returns a hex string"
  (with-output-to-string
      (*standard-output*)
    (serapeum:do-each (o addr)
      (format *standard-output* "~2,'0x" o)
      )))

(defun seq-octstr->nums (str-seq)
  (let ((return-value (copy-seq str-seq)))
    (map-into
     return-value
     #'(lambda(ostr)
	 (parse-integer ostr :radix 16))
     str-seq)))

(defun hexstring->ip-addr (str)
  ;; I don't know if /proc outputs NBO or whatever the machine has.
  ;; Does /proc display the same values on bigendian as it does on
  ;; little endian?.  I have an ARM and an x86 to test with
  (declare (type string str))
  (let ((len (length str)))
    (declare (type integer len))
    (loop :for i integer from len downto 0 by 2
       :when (> i 0)
       :collect (parse-integer str :start (- i 2) :end i :radix 16)
       ))
  )

(defun parse-machine-hex (raw-hex)
  "Return a number for the hex string. Calls parse-integer to do the
actual parsing.  See also: hexstring->octets, parse-integer"
  (octets->num (hexstring->octets raw-hex) :endian (fixnum-info))
  )


(defvar *a-start* (octets->num '(10 0 0 0)))
(defvar *a-end*   (octets->num '(10 255 255 255)))

;; A	10.0.0.0 to 10.255.255.255	255.0.0.0
;; B	172.16.0.0 to 172.31.255.255	255.240.0.0
;; C	192.168.0.0 to 192.168.255.255	255.255.0.0

(defun private-a? (ipaddr)
  "Is the IP address a private A?"
  (trivia:match
      ipaddr
    ((guard x (numberp x))
     (and (>= ipaddr *a-start*)
	  (<= ipaddr *a-end*)))
    ((guard x (or (list x) (vector x)))
     (private-a? (octets->num x)))
    (otherwise
     (error "Unexpected parameter ~a" ipaddr)))
  )

(defun read-octets (n stream)
  (loop :for i :below n :collect (read-byte stream)))

(defmacro gen-num-writers (name num-octets)
  (let ((function-name (intern (string-upcase (format nil "write-~a" name))))
	(seq-write (intern (string-upcase (format nil "write-~a-to-seq" name))))
	)
    `(progn
       (defmethod ,seq-write ((num number)   &key (endian *hw-numerical-type*))
	   (num->octets num :endian endian :length ,num-octets))
       (defmethod ,function-name ((out-stream stream) (num number)  &key (endian *hw-numerical-type*))
	 (write-sequence (num->octets num :endian endian :length ,num-octets) out-stream))))
  )

(defmacro gen-num-reader (name num-octets)
  
  (let ((function-name (intern (string-upcase (format nil "read-~a" name))))
	)
    `(progn
       (defmethod ,function-name ((port stream) &key (endian :big-endian))
	 (let ((buff (make-array ,num-octets)))
	   (read-sequence buff port)
	   (octets->num buff :endian endian)))
       (defmethod ,function-name ((seq sequence) &key (endian :big-endian))
	 (let ((buff (subseq seq 0 ,num-octets)))
	   (values (octets->num buff :endian endian)
		   (subseq seq ,num-octets))))
       )
    ))


(defmacro defnumrw (num-octets)
  (cons
   'progn
   (loop :with i = 1
      :while (<= i num-octets)
      :collect (let ((intdef (intern (string-upcase (format nil "uint~a" (* 8 i))))))
		 `(progn
		    (gen-num-reader ,intdef ,i)
		    (gen-num-writers ,intdef ,i)))
      :do (setf i (* i 2))
      )
   )
  )

(defnumrw 8)
  

