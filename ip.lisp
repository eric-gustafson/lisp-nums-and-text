;;;; snot.lisp
(in-package #:nums-and-txt)

(defvar *private-a-start* '(10 0 0 0))
(defvar *private-a-end*   '(10 255 255 255))

(defun fixnum-info ()
  "Returns :little-endian or :bigendian which should be found in the *features* list for the numerical disposition of hte hardware on the machine that is running the computation"
  #+(or little-endian) (return-from fixnum-info :little-endian)
  #+(or big-endian) (return-from fixnum-info :big-endian) )

(defvar *hw-numerical-type* (fixnum-info)
  "  A dynamic variable that controls how IP addresses and numbers are
  computed.

  The code could be performing a computation for a target for
  instance, and we want to ignore the integer-hw-type of the machine
  that is doing the computation."
  )


(defmethod addr->dotted ((obj list))
  "Convert the address into dotted string"
  (format nil "~{~a.~}" obj)  
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

(defmethod print-ipaddr ((obj vector) stream)
  ;; only handles ipv4 at the moment
  (labels ((doit (a b c d)
  (match
      obj
    ((vector a b c d)
     (print-unreadable-object
	 (obj stream :type t)
       (format stream "~a.~a.~a.~a" a b c d)
       ))
    (otherwise
     (error "Illegal IP Vector value ~a" obj)))
  )

(defun na->list (n)
  ;; Takes a native integer fixnum, like from a packet sniffer
  (loop for i from 0 upto 3
     collect (ldb (byte 8 (* 8 i)) n)))

(defun na->dotted-string (n)
  (sockets:integer-to-dotted n))

(defun dotted->vector (str)
  "Take a number in dotted notation and return a vector representation."
  (declare (type string str))
  (let ((v (serapeum:vect)))
    (loop :for num string in (split-sequence #\. str)
       :do (vector-push-extend  (parse-integer num) v))
    v
    )
  )

(defun dotted->list (str)
  (declare (type string str))
  (loop :for num string in (split-sequence #\. str)
     :collect  (parse-integer num) )
  )

(defun parse-dotted (str)
  (dotted->list str))

(defun dotted->num (str)
  (octets->num (net-octets->host (dotted-to-vector str))) )

(defun _num->octets (num &key length)
  "Takes a lisp number (machine) and turns it into an octet"
  (reverse
   (loop :for i integer from 0
      :while (or (> num  0)
		 (and (numberp length)
		      (> length 0)))
      :collect (ldb (byte 8 0) num)
      :do (progn
	    (setf num (ash num -8))
	    (decf length))
      )
   ))

(defun num->dotted (num &key length)
  (format nil "~{~a~^.~}" (num->octets num :length length)))


(defun num->octets (num &key (endian :big-endian) length)
  ;; Defaults to network byte order
  "Takes a number and returns that number as a list of octets in either big or little endian"
  (ecase endian
    ((:big-endian :network :big :b :n :net)
     #+(or big-endian) (_num->octets num :length length)
     #+(or little-endian) (reverse (_num->octets num :length length))
     )
    ((:little-endian :little :l)
     #+(or big-endian) (_num->octets num :length length)
     #+(or little-endian) (reverse (_num->octets num :length length))
     )
    )
  )

(defun htoa(haddr-uint32)
  "take a uint32 in host byte order and turn it into an ip address string"
  (let ((A (gethash haddr-uint32 *htoa-cache*)))
    (unless (stringp A)
      (setf A (handler-case
		  (multiple-value-bind
			(ipaddress more-addresses canonical-name more-hostnames)
		      (sockets:lookup-hostname haddr-uint32)
		    canonical-name)
		(resolver-fail-error ()
		  (sockets:integer-to-dotted haddr-uint32))
		(resolver-no-name-error ()
		  (sockets:integer-to-dotted haddr-uint32))))
      (setf (gethash haddr-uint32 *htoa-cache*) A))
    A))


(defun ntoa (naddr)
  "Takes an ipv4 network address (4 bytes) and returns the hostname.
This will cache the value for an extended amount of time.  This will
also handle any errors from the dns resolver."
  (htoa (swap-bytes:ntohl naddr))
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
	      (setf acc (ash acc 8)) ;; shift left (up) 8
	      (setf (ldb (byte 8 0) acc) octet)
	      acc)
	  seq
	  :initial-value 0))

(defun octets->num (oct-seq &key (endian :big-endian))
  (ecase
      type
    ((:big-endian :network :big :b :n :net)
     #+(or big-endian) (_octets->num oct-seq)
     #+(or little-endian) (_octets->num (reverse oct-seq))
     )
    ((:little-endian :little :l)
     #+(or big-endian) (_octets->num (reverse oct-seq))
     #+(or little-endian) (_octets->num oct-seq)
     )
    )
  )
			     

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

