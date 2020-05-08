;;;; ip.lisp
(in-package #:numex)

(defvar *a-start* (octets->num '(10 0 0 0)))
(defvar *a-end*   (octets->num '(10 255 255 255)))

(defclass ip-net ()
  (
   (first-ip :accessor first-ip :initform '() :initarg :first-ip)
   (last-ip  :accessor last-ip :initform '()  :initarg :last-ip)
   (netmask :accessor netmask :initform '() :initarg :netmask)
   )
  )



(defmethod print-object ((obj ip-net) stream)
  (print-unreadable-object
      (obj stream :type t)
    (with-slots
	  (first-ip last-ip netmask)
	obj
      (format stream "first:~a,last:~a,net:~a"
	      (num->octets first-ip)
	      (num->octets last-ip)
	      (num->octets netmask))
      )
    )
  )


(defun int32u-upper-nibbles (nnibs)
  (let ((val 0))
    (loop for i from 0 upto nnibs :do
	 (setf (ldb (byte 4 (- 28 (* i 4))) val) 15))
    val
    )
  )

;; A	10.0.0.0 to 10.255.255.255	255.0.0.0
;; B	172.16.0.0 to 172.31.255.255	255.240.0.0
;; C	192.168.0.0 to 192.168.255.255	255.255.0.0
(defvar *privnet-a* (make-instance 'ip-net :first-ip (octets->num #(10 0 0 0)) :last-ip (octets->num #(10 255 255 255)) :netmask (int32u-upper-nibbles 1)))
(defvar *privnet-b* (make-instance 'ip-net :first-ip (octets->num #(172 16 0 0)) :last-ip (octets->num #(172 31 255 255)) :netmask (int32u-upper-nibbles 2)))
(defvar *privnet-c* (make-instance 'ip-net :first-ip (octets->num #(196 168 0)) :last-ip (octets->num #(192 168 255 255)) :netmask (int32u-upper-nibbles 3)))

(defun private-a? (ipaddr)
  "Is the IP address a private A?"
  (cond
    ((numberp ipaddr)
     (and (>= ipaddr *a-start*)
	  (<= ipaddr *a-end*)))
    ((or (listp ipaddr) (vectorp ipaddr))
     (private-a? (octets->num ipaddr)))
    (t
     (error "Unexpected parameter ~a" ipaddr)))
  )

(defmethod subnets-splits-count  ((obj ip-net) bits)
  "how many subnets"
  (ash (lognot (netmask obj)) (* -1 bits)))
 
(defmethod address-bits ((obj ip-net))
  "compute the number of bits in the netmask for the ip-net object"
  (let ((mask (logand #xffffffff (lognot (netmask obj)))))
    (loop :while (> mask 0)
       :counting (> (logand 1 mask) 0) :into numbits
       :do
       (progn
	 (setf mask (ash mask -1))
	 (print mask))
       :finally (return numbits)))
  )

(defmethod netmask-bits ((obj ip-net))
  (let ((mask (logand #xffffffff (netmask obj))))
    (loop :while (> mask 0)
       :counting (> (logand 1 mask) 0) :into numbits
       :do
       (progn
	 (setf mask (ash mask -1))
	 (print mask))
       :finally (return numbits)))
  )

