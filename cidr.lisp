;;;; cidr.lisp
(in-package #:numex)


(defun make-cidr-mask (ncidr-bits)
  (loop
     :with mask = #x80000000
     :repeat (- ncidr-bits 1)
     :do
     (setf mask (logior mask (ash mask -1)))
     :finally (return mask)))

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

(defmethod cidr-bcast (address (cidr integer))
  (assert (and (> cidr 0)  (<= cidr 32)))  
  (let ((ipn (->num  address))
	(cm (make-cidr-mask cidr)))
    (logior ipn (lognot cm))))
  
(defmethod cidr-net-eq? (addrA addrB (cidr integer))
  (eq (cidr-net addrA cidr) (cidr-net addrB cidr)))


#+nil(defmethod ip-cidr->net (address (cidr integer))
  (assert (and (> cidr 0)
	       (<= cidr 32)))
  (let ((ip (->num  address))
	(cm (make-cidr-mask cidr)))
    (logand ip (make-cidr-mask cidr) #xffffffff)
    ))

(defmethod cidr-net-increment ((cidr integer))
  "Returns an integer that will allow you to increment through networks that have this cidr block"
  (1+ (logand #xffffffff (lognot (make-cidr-mask cidr))))
  )

(defmethod cidr-numnets ((cidr integer))
  "Returns the number of cidr nets for the given mask"
  (expt 2 (- 32 cidr)))

;; (cidr-subnets #(10 0 0 0) 16 24)
;;   -> 10.0.0.0 10.0.1.0 10.0.2.0 ...
(defmethod cidr-subnets (addr cidr-net cidr-subnet)
  "Break out a smaller subset of networks from the bigger network"
  (let ((net (cidr-net addr cidr-net))
	(nets (expt 2 (- cidr-subnet cidr-net)))
	(itr (cidr-net-increment 24)))
    (loop
       :for i :from (cidr-net addr cidr-net) :by itr
       :while (cidr-net-eq? addr i cidr-net)
       :collect i)
    )
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

(defmethod cidr-networks (address (cidr integer))
  "Returns all of the networks for this address and cidr-mask"
  
  )

(defmethod cidr-bcast-addr ((cidr integer))
  (assert (and (> cidr 0)  (<= cidr 32)))
  (logand #xffffffff (lognot (make-cidr-mask cidr)))
  )
