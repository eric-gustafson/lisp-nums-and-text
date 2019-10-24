;;;; cidr.lisp
(in-package #:numex)


(defun make-cidr-mask (ncidr-bits)
  (loop
     :with mask = #x80000000
     :repeat (- ncidr-bits 1)
     :do
     (setf mask (logior mask (ash mask -1)))
     :finally (return mask)))

(defmethod ip-cidr->net ((ip integer) (cidr integer))
  (assert (and (> cidr 0)
	       (<= cidr 32)))
  (logand ip (make-cidr-mask cidr) #xffffffff)
  )

(defmethod ip-cidr->sub ((ip integer) (cidr integer))
  (assert (and (> cidr 0)
	       (<= cidr 32)))
  (logand ip (lognot  (make-cidr-mask cidr)) #xffffffff)
  )

(defmethod cidr-range ((cidr integer))
  (assert (and (> cidr 0)
	       (<= cidr 32)))
  (logand #xffffffff (lognot (make-cidr-mask cidr)))
  )

(defmethod cidr-max-addr ((cidr integer))
  (assert (and (> cidr 0)  (<= cidr 32)))
  (1- (logand #xffffffff (lognot (make-cidr-mask cidr))))
  )



(defmethod cidr-net (address (cidr integer))
  (assert (and (> cidr 0) (<= cidr 32)))		      
  (let ((ipn (->num  address))
	(cm (make-cidr-mask cidr)))
    (logand #xffffffff cm ipn))
  )

(defmethod cidr-net-increment ((cidr integer))
  "Returns an integer that will allow you to increment through networks that have this cidr block"
  (1+ (logand #xffffffff (lognot (make-cidr-mask cidr))))
  )
  
(defmethod cidr-num-addresses ((cidr integer))
  "Returns how many addresses are in the cidr"
  (assert (and (> cidr 0)	       (<= cidr 32)))
  (1+ (logand #xffffffff (lognot (make-cidr-mask cidr))))
  )

(defmethod cidr-num-hosts ((cidr integer))
  (assert (and (> cidr 0)	       (<= cidr 32)))
  (1- (logand #xffffffff (lognot (make-cidr-mask cidr))))
  )

(defmethod cidr-addresses (address (cidr integer))
  (assert (and (> cidr 0) (<= cidr 32)))
  (let ((ipn (cidr-net  address cidr))
	(n (cidr-num-addresses cidr)))
    (loop
       :repeat n
       :for i :from ipn :collect i)
    ))


(defmethod cidr-bcast-addr ((cidr integer))
  (assert (and (> cidr 0)  (<= cidr 32)))
  (logand #xffffffff (lognot (make-cidr-mask cidr)))
  )
