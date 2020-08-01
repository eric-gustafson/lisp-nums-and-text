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

(defmethod ->dotted ((obj list))
  "Convert the address into dotted string"
  (format nil
	  ;;;"~{~3,'0d~^.~}"
	  "~{~d~^.~}"
	  obj)  
  )

(defmethod ->dotted ((obj vector))
  "Convert the address into dotted string"
   (->dotted (coerce obj 'list))
  )

(defun num->dotted (num &key (length 4))
  "Converts a machine number representing an IP address into a dotted
string"
  (format nil
	  ;;"~{~3,'0d~^.~}"
	  "~{~d~^.~}"
	  (coerce (num->octets num :length length) 'list))
  )

(defmethod ->dotted ((obj number))
  (->dotted (num->octets obj))
  )

(defmethod ->dotted ((obj string))
  obj)

(defun print-ipaddr (obj stream)
  ;; only handles ipv4 at the moment
  (labels ((doit (a b c d)
	     (print-unreadable-object
		 (obj stream :type t)
	       (format stream "~a.~a.~a.~a" a b c d)
	       )))
    (optima:match
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

#+nil(defparameter *hexstr-scanner*
  (ppcre:create-scanner
   '(:greedy-repetition
     1 nil
     (:SEQUENCE
      (:GREEDY-REPETITION 1 2
       (:CHAR-CLASS (:RANGE #\a #\f) (:RANGE #\A #\F) (:RANGE #\0 #\9)))
      (:greedy-repetition 0 nil #\:)))))

(defparameter *hexstr-scanner*
  (ppcre:create-scanner
   '(:SEQUENCE
     (:GREEDY-REPETITION 1 2
      (:CHAR-CLASS (:RANGE #\a #\f) (:RANGE #\A #\F) (:RANGE #\0 #\9)))
     (:greedy-repetition 0 nil #\:))))
     

(defun dotted->vector (str)
  "Take a number in dotted notation and return a vector representation."
  (declare (type string str))
  (optima:match
      str
    ((optima.ppcre:ppcre *ip-cidr-scanner* ip _)
     ;; 172.21.18.6/24
     (dotted->vector ip))
    ((optima.ppcre:ppcre *ip-scanner*)
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


#+nil(defun hostnum->octets (num &key (num-octets 4))
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

(defun bele (k)
  "returns either :big or :little endian"
  (ecase
      k
    ((:big-endian :network :big :b :n :net) :be)
    ((:little-endian :little :l) :le)))    

(defun num->oct-seq (num)
  "Turns a bignum into a series of octets.  We take the bits off so
that the sequence (HO .. LO), high-order at the beggining of the list,
low order at the end.  We start taking off low order bits and we
terminate when num becomes 0 from taking bits off."
  (let (result)
    (loop :while (> num 0) :do
      (push (ldb (byte 8 0) num) result)
      (setf num (ash num -8)))
    result)
  )

(export 'num->oct-seq)

(defun num->octets (num &key (octets-endian :big-endian) (length 4))
  "Takes a number and returns that number as a list of octets in either big or little endian/
	| answer | number (machine) | todo    |
	|--------+------------------+---------|
	| :be    | :be              | nothing |
	| :be    | :le              | reverse |
	| :le    | :be              | reverse |
	| :le    | :le              | nothing |
"
  (let* ((nbo (bele octets-endian))
	 (machine-rep #+(or big-endian) :be
		      #-(or big-endian) :le)
	 (slen length)
	 (seq (make-array slen)))
    (loop :for i integer from 0 below slen
       :do
	 (setf (elt seq i) (ldb (byte 8 (* 8 i)) num))
       ;;(setf num (ash num -8)) ;; shift right
	 )
    (if (eq nbo machine-rep)
	seq
	(reverse seq))
    )
  )

(defun hexstring->octets (str)
  (loop :for str :in (ppcre:all-matches-as-strings *hexstr-scanner* str)
	:collect (parse-integer (remove #\: str) :radix 16))
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

(defun octets->num (oct-seq &key (octets-endian :big-endian))
  "Turn a series of octets into a machine number.  The endian keyword parameter describes the endianess of the oct-seq parameter."
  (check-type oct-seq sequence)  
  (ecase
      octets-endian
    ((:big-endian :network :big :b :n :net)
     (_octets->num  oct-seq)
     )
    ((:little-endian :little :l)
     (_octets->num (reverse oct-seq))
     )
    )
  )

(defun seq->num (seq &key (endian :big-endian))
  (octets->num seq :octets-endian endian))

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

(defun octet-list->hexstr/colons (addr)
  "Send in any sequence of octets, and this returns a hex string"
  (with-output-to-string
      (*standard-output*)
    (loop :for  (item . rest) :on addr
	 :do
	 (format *standard-output* "~2,'0x" item)
	 :when rest :do (format t ":"))
    ))

(defun octseq->hexstr (seq)
  "converts a sequence of octets into a hex string. The numbers in the
seq are always displayed with left padded 0, so #(0 1) => '00:01'"
  (let ((port (reduce #'(lambda(port item)
			  (cond
			    (port
			     (format port ":~2,'0x" item)
			     port
			     )
			    (t
			     (let ((p (make-string-output-stream)))
			       (format p "~2,'0x" item)
			       p))))
		      seq
		      :initial-value nil
		      )))
    (get-output-stream-string  port))
  )

(export 'octseq->hexstr)

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


(defun read-octets (n stream)
  (loop :for i :below n :collect (read-byte stream)))

(defmacro gen-num-writers (name num-octets)
  (let ((function-name (intern (string-upcase (format nil "write-~a" name))))
	(seq-write (intern (string-upcase (format nil "write-~a-to-seq" name))))
	)
    `(progn
       (defmethod ,seq-write ((num number)   &key (endian *hw-numerical-type*))
	   (num->octets num :octets-endian endian :length ,num-octets))
       (defmethod ,function-name ((out-stream stream) (num number)  &key (endian *hw-numerical-type*))
	 (write-sequence (num->octets num :octets-endian endian :length ,num-octets) out-stream))))
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

(defgeneric ->num (obj)
  (:documentation "Turn a dotted ip address, like 127.0.0.1 or a
  sequences like that, such as #(127 0 0 1) into a machine number. If
  you pass it a number, then it's returns that number (identity
  function).")
  (:method ((obj string))
    (dotted->num obj))
  (:method ((obj sequence))
    (seq->num obj))
  (:method ((obj number))
    obj)
  )


(defgeneric ->octets (obj)
  (:documentation "Turn a thing into a vector that represents an 32 bit IP address in network byte order")
  (:method ((obj number))
    (num->octets obj :octets-endian :net))
  (:method ((obj sequence))
    (map 'vector #'values obj))
  )

(export '->octets)
